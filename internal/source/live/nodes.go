// Collecte des NŒUDS PHYSIQUES (workers) et du placement des pods.
//
// Ajoute un nœud graphe par Node Kubernetes (couche infra) et une arête
// RUNS_ON (Pod -> Node) via pod.spec.nodeName. Sert deux choses :
//   - voir « quels pods tournent sur quel worker » (placement) ;
//   - fonder l'évasion conteneur -> hôte -> pods voisins du futur onglet
//     « chemins d'attaque » (un node compromis atteint tous ses pods).
//
// Lecture seule : on ne lit que metadata + spec.nodeName. Aucune donnée
// sensible (kubelet, credentials) n'est touchée.
package live

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubegraph/internal/graph"
)

// collectNodes liste les Nodes du cluster et rattache chaque pod à son worker.
// Non bloquant : si la liste des Nodes échoue (RBAC manquant), on retourne vide
// et le reste du graphe reste valide.
func (s *Source) collectNodes(ctx context.Context, pods []corev1.Pod) ([]graph.Node, []graph.Edge) {
	list, err := s.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil
	}

	var nodes []graph.Node
	// nom du worker -> UID (pour résoudre pod.spec.nodeName en cible d'arête).
	uidByName := make(map[string]string, len(list.Items))
	for i := range list.Items {
		nd := &list.Items[i]
		uidByName[nd.Name] = string(nd.UID)
		gn := s.node(&nd.ObjectMeta, "Node", graph.LayerInfra)
		if len(nd.Status.Addresses) > 0 {
			for _, a := range nd.Status.Addresses {
				if a.Type == corev1.NodeInternalIP {
					gn.IP = a.Address
					break
				}
			}
		}
		nodes = append(nodes, gn)
	}

	id := func(uid string) graph.NodeID { return graph.NodeID{ClusterID: s.clusterID, UID: uid} }
	var edges []graph.Edge
	for i := range pods {
		p := &pods[i]
		if p.Spec.NodeName == "" {
			continue
		}
		nodeUID, ok := uidByName[p.Spec.NodeName]
		if !ok {
			continue
		}
		edges = append(edges, graph.Edge{From: id(string(p.UID)), To: id(nodeUID), Type: graph.EdgeRunsOn})
	}
	return nodes, edges
}
