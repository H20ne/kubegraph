// Package declared lit l'état DÉCLARÉ depuis un dossier de manifestes YAML
// RENDUS (helm template / kustomize build faits en amont), et calcule la dérive
// GitOps « déclaré vs observé » au niveau PRÉSENCE (Phase 4a).
//
// Le rendu (Helm/Kustomize) n'est PAS embarqué : on consomme du YAML applicable.
// Les CRD et types inconnus du scheme built-in sont ignorés (workloads,
// services, RBAC… suffisent pour la dérive de présence).
//
// Trois états, posés sur graph.Node.Drift :
//   - insync    : déclaré ET observé.
//   - missing   : déclaré mais pas observé (pas déployé, rollout raté…). Un nœud
//     fantôme est ajouté (Origin=declared).
//   - unmanaged : observé mais pas déclaré (hors Git). SEULEMENT pour les kinds
//     DÉCLARABLES : Pods/ReplicaSets/EndpointSlices sont générés, jamais jugés.
package declared

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/kubernetes/scheme"

	"kubegraph/internal/graph"
)

// Ident identifie une ressource déclarée par son identité stable.
type Ident struct{ Kind, Namespace, Name string }

// declarable : kinds qu'un dépôt GitOps est censé déclarer. On exclut ce que le
// cluster GÉNÈRE (Pod, ReplicaSet, EndpointSlice…) et nos nœuds synthétiques
// (Secret déduit des specs — jamais un objet réel ici).
var declarable = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"Job": true, "CronJob": true, "Service": true, "Ingress": true,
	"ConfigMap": true, "NetworkPolicy": true, "ServiceAccount": true,
	"Role": true, "ClusterRole": true, "RoleBinding": true, "ClusterRoleBinding": true,
	"HorizontalPodAutoscaler": true, "PodDisruptionBudget": true, "PersistentVolumeClaim": true,
}

// excludedNS : namespaces d'infra rarement gérés par le Git applicatif de l'user
// → on ne les juge pas « hors Git » pour éviter un flot de faux positifs.
var excludedNS = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
	"calico-system": true, "calico-apiserver": true, "tigera-operator": true,
}

// layerOf : couche fonctionnelle d'un kind (pour l'affichage des nœuds fantômes).
func layerOf(kind string) graph.Layer {
	switch kind {
	case "Service", "Ingress", "NetworkPolicy":
		return graph.LayerNetworking
	case "ConfigMap", "HorizontalPodAutoscaler":
		return graph.LayerConfig
	case "PersistentVolumeClaim":
		return graph.LayerStorage
	case "ServiceAccount", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "PodDisruptionBudget":
		return graph.LayerSecurity
	default:
		return graph.LayerWorkload
	}
}

// Load lit récursivement un dossier de YAML/JSON rendus et retourne les identités
// déclarées (kinds déclarables uniquement).
func Load(dir string) ([]Ident, error) {
	dec := scheme.Codecs.UniversalDeserializer()
	var out []Ident
	// add décode UN document. Un « List » (ce que produit `kubectl get -o yaml`)
	// est déroulé : chaque item est re-décodé. Le reste est ignoré silencieusement
	// (CRD, type inconnu, non-K8s).
	var add func(doc []byte)
	add = func(doc []byte) {
		if len(bytes.TrimSpace(doc)) == 0 {
			return
		}
		obj, gvk, e := dec.Decode(doc, nil, nil)
		if e != nil || gvk == nil {
			return
		}
		if gvk.Kind == "List" {
			if l, ok := obj.(*corev1.List); ok {
				for _, it := range l.Items {
					if len(it.Raw) > 0 {
						add(it.Raw)
					}
				}
			}
			return
		}
		if !declarable[gvk.Kind] {
			return
		}
		m, e := meta.Accessor(obj)
		if e != nil {
			return
		}
		out = append(out, Ident{Kind: gvk.Kind, Namespace: m.GetNamespace(), Name: m.GetName()})
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml", ".json":
		default:
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil // fichier illisible : non bloquant
		}
		for _, doc := range bytes.Split(b, []byte("\n---")) {
			add(doc)
		}
		return nil
	})
	return out, err
}

// ApplyDrift stampe le Drift sur les nœuds observés et ajoute les nœuds fantômes
// (déclaré non observé). Retourne la liste de nœuds augmentée.
func ApplyDrift(clusterID string, nodes []graph.Node, decl []Ident) []graph.Node {
	key := func(kind, ns, name string) string { return kind + "/" + ns + "/" + name }
	declaredSet := map[string]bool{}
	for _, d := range decl {
		declaredSet[key(d.Kind, d.Namespace, d.Name)] = true
	}
	observedSet := map[string]bool{}
	for i := range nodes {
		n := &nodes[i]
		if !declarable[n.Kind] || excludedNS[n.Namespace] {
			continue
		}
		k := key(n.Kind, n.Namespace, n.Name)
		observedSet[k] = true
		if declaredSet[k] {
			n.Drift = "insync"
		} else {
			n.Drift = "unmanaged"
		}
	}
	// Fantômes : déclaré mais pas observé.
	for _, d := range decl {
		if excludedNS[d.Namespace] {
			continue
		}
		k := key(d.Kind, d.Namespace, d.Name)
		if observedSet[k] {
			continue
		}
		nodes = append(nodes, graph.Node{
			ID:     graph.NodeID{ClusterID: clusterID, UID: "declared:" + k},
			Kind:   d.Kind, Namespace: d.Namespace, Name: d.Name,
			Layer: layerOf(d.Kind), Origin: graph.OriginDeclared, Drift: "missing",
		})
	}
	return nodes
}
