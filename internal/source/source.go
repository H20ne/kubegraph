// Dépendances réseau DÉCLARÉES : lues depuis les NetworkPolicy (networking.k8s.io).
//
// Une NetworkPolicy dit quel trafic est AUTORISÉ vers/depuis les pods qu'elle
// cible. On la traduit en arêtes ALLOWS au niveau WORKLOAD (source -> cible), ce
// qui donne la « base déclarée » à comparer au trafic réellement observé
// (TALKS_TO) : observé mais non autorisé = dérive de sécurité réseau.
//
// Non bloquant : si l'accès aux NetworkPolicies échoue, l'outil fonctionne sans.
// Périmètre volontairement CONSERVATEUR (évite les faux positifs) : on modélise
// les règles Ingress à base de podSelector (même namespace, ou namespaceSelector
// via labels de namespace). Les pairs ipBlock (externe) et « from vide = tout
// autorisé » ne produisent pas d'arête — la comparaison de dérive côté front ne
// juge un flux QUE si sa cible porte au moins une règle ALLOWS.
package live

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"kubegraph/internal/graph"
)

// collectNetpol retourne les nœuds NetworkPolicy et les arêtes ALLOWS.
//   - pods    : tous les pods du cluster (pour matcher les sélecteurs).
//   - topWL   : pod UID -> workload de tête UID (Deployment/StatefulSet/DaemonSet).
//   - nsLabels: nom de namespace -> ses labels (pour les namespaceSelector).
func (s *Source) collectNetpol(ctx context.Context, pods []corev1.Pod, topWL map[string]string, nsLabels map[string]labels.Set) ([]graph.Node, []graph.Edge) {
	list, err := s.client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil // NetworkPolicies inaccessibles : non bloquant.
	}

	// Index des pods par namespace.
	byNs := map[string][]*corev1.Pod{}
	for i := range pods {
		p := &pods[i]
		byNs[p.Namespace] = append(byNs[p.Namespace], p)
	}
	id := func(uid string) graph.NodeID { return graph.NodeID{ClusterID: s.clusterID, UID: uid} }

	// Workloads des pods d'un namespace qui matchent un sélecteur (podSelector vide = tous).
	matchWorkloads := func(ns string, sel labels.Selector) map[string]bool {
		out := map[string]bool{}
		for _, p := range byNs[ns] {
			if sel.Matches(labels.Set(p.Labels)) {
				if wl := topWL[string(p.UID)]; wl != "" {
					out[wl] = true
				}
			}
		}
		return out
	}

	var nodes []graph.Node
	var edges []graph.Edge
	seen := map[graph.Edge]bool{}
	addAllow := func(from, to string) {
		if from == "" || to == "" || from == to {
			return
		}
		e := graph.Edge{From: id(from), To: id(to), Type: graph.EdgeAllows}
		if !seen[e] {
			seen[e] = true
			edges = append(edges, e)
		}
	}

	for i := range list.Items {
		np := &list.Items[i]
		ns := np.Namespace

		nodes = append(nodes, graph.Node{
			ID: id(string(np.UID)), Kind: "NetworkPolicy", Namespace: ns, Name: np.Name,
			Labels: np.Labels, Layer: graph.LayerSecurity, Origin: graph.OriginObserved,
		})

		targetSel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			continue
		}
		targets := matchWorkloads(ns, targetSel) // workloads protégés par cette policy

		// Règles Ingress : chaque pair "from" autorisée -> ALLOWS(source -> cible).
		for _, rule := range np.Spec.Ingress {
			for _, peer := range rule.From {
				// ipBlock (source externe : ni podSelector ni namespaceSelector) : hors périmètre.
				if peer.PodSelector == nil && peer.NamespaceSelector == nil {
					continue
				}
				// Sélecteur de pods : celui fourni, sinon TOUS les pods
				// (cas fréquent : namespaceSelector seul = « tout le namespace X »).
				psel := labels.Everything()
				if peer.PodSelector != nil {
					ps, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
					if err != nil {
						continue
					}
					psel = ps
				}
				// Namespaces sources : ceux du namespaceSelector, sinon le même namespace.
				srcNamespaces := []string{ns}
				if peer.NamespaceSelector != nil {
					nsel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
					if err != nil {
						continue
					}
					srcNamespaces = nil
					for name, lbls := range nsLabels {
						if nsel.Matches(lbls) {
							srcNamespaces = append(srcNamespaces, name)
						}
					}
				}
				for _, sns := range srcNamespaces {
					for src := range matchWorkloads(sns, psel) {
						for tgt := range targets {
							addAllow(src, tgt)
						}
					}
				}
			}
		}
	}
	return nodes, edges
}
