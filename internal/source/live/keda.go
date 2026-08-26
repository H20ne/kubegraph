// Dépendances KEDA : lues via le client dynamique (CRD keda.sh).
//
// Un ScaledObject déclare quel Deployment il scale (scaleTargetRef) et par quels
// déclencheurs (triggers, ex : Kafka). Ces liens traversent souvent les
// namespaces (le Kafka vit dans son namespace, le workload dans un autre) et
// n'existent PAS comme arêtes natives K8s — c'est tout l'intérêt de les ajouter.
package live

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"kubegraph/internal/graph"
)

var scaledObjectGVR = schema.GroupVersionResource{
	Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects",
}

// collectKeda retourne les nœuds ScaledObject et leurs arêtes.
// Si KEDA n'est pas installé (ou pas de droits sur la CRD), on ignore
// silencieusement : l'outil reste fonctionnel sans.
func (s *Source) collectKeda(ctx context.Context, deployUID, svcUID map[string]string) ([]graph.Node, []graph.Edge) {
	if s.dyn == nil {
		return nil, nil
	}
	list, err := s.dyn.Resource(scaledObjectGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil // KEDA absent ou CRD non accessible : non bloquant.
	}

	var nodes []graph.Node
	var edges []graph.Edge
	id := func(uid string) graph.NodeID { return graph.NodeID{ClusterID: s.clusterID, UID: uid} }

	for i := range list.Items {
		o := &list.Items[i]
		ns := o.GetNamespace()
		soID := id(string(o.GetUID()))
		nodes = append(nodes, graph.Node{
			ID: soID, Kind: "ScaledObject", Namespace: ns, Name: o.GetName(),
			Labels: o.GetLabels(), Layer: graph.LayerConfig, Origin: graph.OriginObserved,
		})

		// ScaledObject -> Deployment ciblé (même namespace).
		if target, _, _ := unstructured.NestedString(o.Object, "spec", "scaleTargetRef", "name"); target != "" {
			if duid, ok := deployUID[ns+"/"+target]; ok {
				edges = append(edges, graph.Edge{From: soID, To: id(duid), Type: graph.EdgeScales})
			}
		}

		// Déclencheurs : on tente de rattacher chaque trigger à un Service
		// existant (ex : le Kafka référencé par bootstrapServers), cross-namespace.
		triggers, _, _ := unstructured.NestedSlice(o.Object, "spec", "triggers")
		seen := map[string]bool{}
		for _, t := range triggers {
			tm, ok := t.(map[string]any)
			if !ok {
				continue
			}
			meta, _, _ := unstructured.NestedStringMap(tm, "metadata")
			for _, v := range meta {
				if suid, ok := matchServiceHost(v, ns, svcUID); ok && !seen[suid] {
					seen[suid] = true
					edges = append(edges, graph.Edge{From: id(suid), To: soID, Type: graph.EdgeTriggers})
				}
			}
		}
	}
	return nodes, edges
}

// matchServiceHost extrait un hôte de service K8s d'une valeur de config et le
// résout en UID de Service. Reconnaît les formes courantes :
//   - "kafka.kafka:9092"                    -> service kafka, namespace kafka
//   - "kafka:9092"                          -> service kafka, namespace courant
//   - "kafka.kafka.svc.cluster.local:9092"  -> service kafka, namespace kafka
//   - listes séparées par des virgules (on prend le premier hôte)
func matchServiceHost(value, defaultNS string, svcUID map[string]string) (string, bool) {
	host := value
	if i := strings.IndexByte(host, ','); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSpace(host)
	// retire un éventuel schéma
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	// retire le port
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return "", false
	}
	parts := strings.Split(host, ".")
	name := parts[0]
	ns := defaultNS
	if len(parts) >= 2 {
		ns = parts[1] // <service>.<namespace>[.svc.cluster.local]
	}
	uid, ok := svcUID[ns+"/"+name]
	return uid, ok
}
