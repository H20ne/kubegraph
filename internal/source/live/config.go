// Dépendances par configuration : « qui est configuré pour appeler qui ».
//
// On scanne la config des workloads (variables d'env, args, command, et les
// ConfigMaps référencées via envFrom) à la recherche de noms de services K8s.
// Chaque référence trouvée devient une arête USES : workload -> service appelé.
//
// LIMITE assumée : c'est du DÉCLARÉ (« configuré pour »), pas de l'OBSERVÉ.
// Le trafic réel viendra d'une source runtime (agent eBPF) sous forme d'arêtes
// TALKS_TO, dans le même graphe — l'écart entre les deux = la vraie valeur.
package live

import (
	"context"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubegraph/internal/graph"
)

// collectConfigDeps retourne les arêtes USES déduites de la config des workloads.
func (s *Source) collectConfigDeps(ctx context.Context, deps *appsv1.DeploymentList, sts *appsv1.StatefulSetList, ds *appsv1.DaemonSetList, svcs *corev1.ServiceList) []graph.Edge {
	// Clés DNS -> UID du service (nom court et nom.namespace).
	svcKeys := make(map[string]string)
	for i := range svcs.Items {
		sv := &svcs.Items[i]
		svcKeys[sv.Name] = string(sv.UID)
		svcKeys[sv.Name+"."+sv.Namespace] = string(sv.UID)
	}

	// Index des ConfigMaps (lecture non bloquante : si refusée, on scanne juste
	// env/args/command).
	cmIndex := make(map[string]*corev1.ConfigMap)
	if cms, err := s.client.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range cms.Items {
			c := &cms.Items[i]
			cmIndex[c.Namespace+"/"+c.Name] = c
		}
	}

	type wl struct {
		uid, ns string
		spec    *corev1.PodSpec
	}
	var workloads []wl
	for i := range deps.Items {
		d := &deps.Items[i]
		workloads = append(workloads, wl{string(d.UID), d.Namespace, &d.Spec.Template.Spec})
	}
	for i := range sts.Items {
		o := &sts.Items[i]
		workloads = append(workloads, wl{string(o.UID), o.Namespace, &o.Spec.Template.Spec})
	}
	for i := range ds.Items {
		o := &ds.Items[i]
		workloads = append(workloads, wl{string(o.UID), o.Namespace, &o.Spec.Template.Spec})
	}

	id := func(uid string) graph.NodeID { return graph.NodeID{ClusterID: s.clusterID, UID: uid} }
	var edges []graph.Edge

	for _, w := range workloads {
		seen := map[string]bool{}
		emit := func(value string) {
			if suid, ok := matchService(value, w.ns, svcKeys); ok && suid != "" && !seen[suid] {
				seen[suid] = true
				edges = append(edges, graph.Edge{From: id(w.uid), To: id(suid), Type: graph.EdgeUses})
			}
		}
		for i := range w.spec.Containers {
			c := &w.spec.Containers[i]
			for _, e := range c.Env {
				if e.Value != "" {
					emit(e.Value)
				}
			}
			for _, a := range c.Args {
				emit(a)
			}
			for _, cmd := range c.Command {
				emit(cmd)
			}
			for _, ef := range c.EnvFrom {
				if ef.ConfigMapRef == nil {
					continue
				}
				if cm := cmIndex[w.ns+"/"+ef.ConfigMapRef.Name]; cm != nil {
					for _, v := range cm.Data {
						emit(v)
					}
				}
			}
		}
	}
	return edges
}

// matchService extrait un hôte de service d'une valeur de config et le résout
// en UID. Reconnaît les URL (http://svc:8080/path), les couples hôte:port, les
// FQDN (svc.ns.svc.cluster.local) et les noms nus.
func matchService(value, defaultNS string, svcKeys map[string]string) (string, bool) {
	host := value
	// après un schéma éventuel
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	// jusqu'au premier séparateur d'autorité
	if i := strings.IndexAny(host, "/ ,?\"'\t\n"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return "", false
	}
	// user@host
	if i := strings.LastIndexByte(host, '@'); i >= 0 {
		host = host[i+1:]
	}
	// host:port
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}

	// essais : host complet, puis deux premiers labels (nom.ns), puis premier
	// label (nom court, résolu dans le namespace du workload).
	if uid, ok := svcKeys[host]; ok {
		return uid, true
	}
	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		if uid, ok := svcKeys[labels[0]+"."+labels[1]]; ok {
			return uid, true
		}
	}
	if len(labels) >= 1 {
		if uid, ok := svcKeys[labels[0]]; ok {
			return uid, true
		}
		// nom court résolu dans le namespace du workload
		if uid, ok := svcKeys[labels[0]+"."+defaultNS]; ok {
			return uid, true
		}
	}
	return "", false
}
