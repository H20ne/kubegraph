// Package resolve calcule les arêtes du graphe à partir des objets Kubernetes.
//
// Il travaille sur les types K8s (appsv1, corev1, networkingv1), pas sur une
// source précise : la source live ET la source Git (manifestes rendus)
// produisent ces mêmes types, donc les resolvers sont partagés entre les deux.
package resolve

import (
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubegraph/internal/graph"
)

// Objects regroupe les objets bruts sur lesquels les resolvers raisonnent.
type Objects struct {
	Deployments []appsv1.Deployment
	ReplicaSets []appsv1.ReplicaSet
	Pods        []corev1.Pod
	Services    []corev1.Service
	Ingresses   []networkingv1.Ingress
}

// Edges applique les trois resolvers du MVP et retourne des arêtes dédupliquées.
func Edges(clusterID string, o Objects) []graph.Edge {
	var edges []graph.Edge
	edges = append(edges, ownedBy(clusterID, o)...)
	edges = append(edges, selects(clusterID, o)...)
	edges = append(edges, routesTo(clusterID, o)...)
	return dedup(edges)
}

func id(clusterID, uid string) graph.NodeID {
	return graph.NodeID{ClusterID: clusterID, UID: uid}
}

// ownedBy : enfant -> propriétaire, via ownerReferences.
// L'UID du propriétaire est directement dans la référence, pas besoin d'index.
func ownedBy(clusterID string, o Objects) []graph.Edge {
	var edges []graph.Edge
	emit := func(m metav1.ObjectMeta) {
		for _, ref := range m.OwnerReferences {
			edges = append(edges, graph.Edge{
				From: id(clusterID, string(m.UID)),
				To:   id(clusterID, string(ref.UID)),
				Type: graph.EdgeOwnedBy,
			})
		}
	}
	for i := range o.Pods {
		emit(o.Pods[i].ObjectMeta)
	}
	for i := range o.ReplicaSets {
		emit(o.ReplicaSets[i].ObjectMeta)
	}
	for i := range o.Deployments {
		emit(o.Deployments[i].ObjectMeta)
	}
	return edges
}

// selects : Service -> Pod, quand les labels du pod couvrent le sélecteur.
// On indexe les pods par namespace pour éviter un balayage O(services*pods).
func selects(clusterID string, o Objects) []graph.Edge {
	var edges []graph.Edge

	podsByNS := make(map[string][]*corev1.Pod)
	for i := range o.Pods {
		p := &o.Pods[i]
		podsByNS[p.Namespace] = append(podsByNS[p.Namespace], p)
	}

	for i := range o.Services {
		svc := &o.Services[i]
		sel := svc.Spec.Selector
		if len(sel) == 0 {
			// Pas de sélecteur (ex : ExternalName, headless) => ne matche rien.
			continue
		}
		for _, p := range podsByNS[svc.Namespace] {
			if matchesLabels(sel, p.Labels) {
				edges = append(edges, graph.Edge{
					From: id(clusterID, string(svc.UID)),
					To:   id(clusterID, string(p.UID)),
					Type: graph.EdgeSelects,
				})
			}
		}
	}
	return edges
}

// matchesLabels vrai si chaque paire du sélecteur est présente à l'identique
// dans les labels.
func matchesLabels(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// routesTo : Ingress -> Service. L'ingress référence le service par son NOM
// (dans son namespace), donc on résout nom -> UID via un index.
func routesTo(clusterID string, o Objects) []graph.Edge {
	var edges []graph.Edge

	svcUID := make(map[string]string) // clé : "namespace/name"
	for i := range o.Services {
		svc := &o.Services[i]
		svcUID[svc.Namespace+"/"+svc.Name] = string(svc.UID)
	}

	edgeFor := func(ingUID, ns, svcName string) (graph.Edge, bool) {
		if svcName == "" {
			return graph.Edge{}, false
		}
		uid, ok := svcUID[ns+"/"+svcName]
		if !ok {
			return graph.Edge{}, false
		}
		return graph.Edge{
			From: id(clusterID, ingUID),
			To:   id(clusterID, uid),
			Type: graph.EdgeRoutesTo,
		}, true
	}

	for i := range o.Ingresses {
		ing := &o.Ingresses[i]
		ns := ing.Namespace
		uid := string(ing.UID)

		if db := ing.Spec.DefaultBackend; db != nil && db.Service != nil {
			if e, ok := edgeFor(uid, ns, db.Service.Name); ok {
				edges = append(edges, e)
			}
		}
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					if e, ok := edgeFor(uid, ns, path.Backend.Service.Name); ok {
						edges = append(edges, e)
					}
				}
			}
		}
	}
	return edges
}

// dedup retire les arêtes en double (un ingress peut router plusieurs fois vers
// le même service). graph.Edge est comparable, on l'utilise comme clé.
func dedup(edges []graph.Edge) []graph.Edge {
	seen := make(map[graph.Edge]struct{}, len(edges))
	out := make([]graph.Edge, 0, len(edges))
	for _, e := range edges {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}
