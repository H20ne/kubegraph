// Dépendances réseau DÉCLARÉES : lues depuis les NetworkPolicy (networking.k8s.io).
//
// Une NetworkPolicy dit quel trafic est AUTORISÉ vers/depuis les pods qu'elle
// cible. On la traduit en arêtes au niveau WORKLOAD :
//   - ALLOWS(source -> cible)       : une règle Ingress autorise "source" à
//     joindre la cible.
//   - ALLOWS(cible -> destination)  : une règle Egress autorise la cible à
//     joindre "destination".
//
// On émet aussi des marqueurs d'ISOLATION, base de la détection de dérive :
//   - PROTECTS_IN(np -> workload)   : le workload est réellement isolé en ENTRÉE.
//   - PROTECTS_OUT(np -> workload)  : le workload est réellement isolé en SORTIE.
// Un flux n'est jugé « dérive » côté front QUE si sa cible (resp. sa source) est
// protégée dans le sens concerné ET que le flux n'est pas dans les ALLOWS.
//
// Périmètre volontairement CONSERVATEUR (évite les faux positifs) :
//   - pairs podSelector / namespaceSelector (via labels de namespace) modélisés ;
//   - pairs ipBlock (externe) ignorées (ni ALLOWS ni influence sur l'isolation) ;
//   - « allow-all » (règle sans from/to, ou namespaceSelector {} sans podSelector)
//     => le workload est marqué OUVERT dans ce sens => pas de marqueur de
//     protection => aucun flux n'est jugé en dérive de ce côté.
//
// Non bloquant : si l'accès aux NetworkPolicies échoue, l'outil fonctionne sans.
package live

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"kubegraph/internal/graph"
)

// collectNetpol retourne les nœuds NetworkPolicy et les arêtes
// ALLOWS / PROTECTS_IN / PROTECTS_OUT.
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

	// Workloads des pods d'un namespace qui matchent un sélecteur (vide = tous).
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

	// peerWorkloads résout un pair (from/to) en workloads.
	//   - retourne isAll=true si le pair vaut « tout autorisé »
	//     (namespaceSelector {} sans podSelector => tous les namespaces).
	//   - un ipBlock (ni podSelector ni namespaceSelector) => (nil, false), ignoré.
	peerWorkloads := func(policyNs string, ps, nsSel *metav1.LabelSelector) (map[string]bool, bool) {
		if ps == nil && nsSel == nil {
			return nil, false // ipBlock (source/destination externe) : hors périmètre.
		}
		if ps == nil && nsSel != nil && len(nsSel.MatchLabels) == 0 && len(nsSel.MatchExpressions) == 0 {
			return nil, true // namespaceSelector {} => tout le cluster => allow-all.
		}
		psel := labels.Everything()
		if ps != nil {
			p, err := metav1.LabelSelectorAsSelector(ps)
			if err != nil {
				return nil, false
			}
			psel = p
		}
		nsList := []string{policyNs}
		if nsSel != nil {
			nsel, err := metav1.LabelSelectorAsSelector(nsSel)
			if err != nil {
				return nil, false
			}
			nsList = nil
			for name, lbls := range nsLabels {
				if nsel.Matches(lbls) {
					nsList = append(nsList, name)
				}
			}
		}
		out := map[string]bool{}
		for _, n := range nsList {
			for w := range matchWorkloads(n, psel) {
				out[w] = true
			}
		}
		return out, false
	}

	var nodes []graph.Node
	var edges []graph.Edge
	seen := map[graph.Edge]bool{}
	add := func(from, to string, t graph.EdgeType) {
		if from == "" || to == "" || from == to {
			return
		}
		e := graph.Edge{From: id(from), To: id(to), Type: t}
		if !seen[e] {
			seen[e] = true
			edges = append(edges, e)
		}
	}

	openIn := map[string]bool{}     // workload -> ingress « allow-all » (pas de protection)
	openOut := map[string]bool{}    // workload -> egress « allow-all »
	protInNp := map[string]string{} // workload isolé en entrée -> UID d'une policy le ciblant
	protOutNp := map[string]string{}

	for i := range list.Items {
		np := &list.Items[i]
		ns := np.Namespace
		npUID := string(np.UID)

		nodes = append(nodes, graph.Node{
			ID: id(npUID), Kind: "NetworkPolicy", Namespace: ns, Name: np.Name,
			Labels: np.Labels, Layer: graph.LayerSecurity, Origin: graph.OriginObserved,
		})

		targetSel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			continue
		}
		targets := matchWorkloads(ns, targetSel) // workloads que cette policy régit

		// policyTypes : quels sens la policy gouverne-t-elle ? Si absent, défaut
		// Kubernetes : Ingress toujours, Egress seulement si des règles egress existent.
		hasIngress, hasEgress := false, false
		if len(np.Spec.PolicyTypes) > 0 {
			for _, pt := range np.Spec.PolicyTypes {
				switch pt {
				case networkingv1.PolicyTypeIngress:
					hasIngress = true
				case networkingv1.PolicyTypeEgress:
					hasEgress = true
				}
			}
		} else {
			hasIngress = true
			hasEgress = len(np.Spec.Egress) > 0
		}

		// ENTRÉE : la cible est isolée en entrée ; chaque pair "from" -> ALLOWS(src -> cible).
		if hasIngress {
			for tgt := range targets {
				if protInNp[tgt] == "" {
					protInNp[tgt] = npUID
				}
			}
			for _, rule := range np.Spec.Ingress {
				if len(rule.From) == 0 { // règle sans pair => autorise TOUTES les sources.
					for tgt := range targets {
						openIn[tgt] = true
					}
					continue
				}
				for _, peer := range rule.From {
					srcs, all := peerWorkloads(ns, peer.PodSelector, peer.NamespaceSelector)
					if all {
						for tgt := range targets {
							openIn[tgt] = true
						}
						continue
					}
					for src := range srcs {
						for tgt := range targets {
							add(src, tgt, graph.EdgeAllows)
						}
					}
				}
			}
		}

		// SORTIE : la cible est isolée en sortie ; chaque pair "to" -> ALLOWS(cible -> dst).
		if hasEgress {
			for tgt := range targets {
				if protOutNp[tgt] == "" {
					protOutNp[tgt] = npUID
				}
			}
			for _, rule := range np.Spec.Egress {
				if len(rule.To) == 0 { // règle sans pair => autorise TOUTES les destinations.
					for tgt := range targets {
						openOut[tgt] = true
					}
					continue
				}
				for _, peer := range rule.To {
					dsts, all := peerWorkloads(ns, peer.PodSelector, peer.NamespaceSelector)
					if all {
						for tgt := range targets {
							openOut[tgt] = true
						}
						continue
					}
					for dst := range dsts {
						for tgt := range targets {
							add(tgt, dst, graph.EdgeAllows)
						}
					}
				}
			}
		}
	}

	// Marqueurs d'isolation : seulement pour les workloads réellement fermés dans
	// le sens concerné (ciblés par une policy ET non « allow-all »).
	for tgt, npUID := range protInNp {
		if !openIn[tgt] {
			add(npUID, tgt, graph.EdgeProtectsIn)
		}
	}
	for tgt, npUID := range protOutNp {
		if !openOut[tgt] {
			add(npUID, tgt, graph.EdgeProtectsOut)
		}
	}

	return nodes, edges
}
