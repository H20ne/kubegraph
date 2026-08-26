// Ressources complémentaires pour « comprendre tout le cluster » :
//   - Jobs / CronJobs (batch)       : le travail ponctuel et planifié.
//   - HorizontalPodAutoscaler (HPA) : le scaling natif (HPA -> workload cible).
//   - PersistentVolumeClaim / PV    : le stockage (workload -> PVC -> PV).
//   - PodDisruptionBudget (PDB)      : la résilience (PDB couvre des workloads).
//
// Arêtes réutilisées (aucun nouveau type) :
//   OWNED_BY  Job -> CronJob
//   SCALES    HPA -> Deployment/StatefulSet (comme KEDA)
//   USES      workload -> PVC, puis PVC -> PV
//   SELECTS   PDB -> workload couvert
//
// Chaque lecture est NON bloquante : si un groupe d'API manque (RBAC absent,
// CRD non installée…), on saute ce type sans casser le reste.
package live

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"kubegraph/internal/graph"
)

// collectWorkloadExtras retourne les nœuds et arêtes des ressources ci-dessus.
//   - pods     : pour les montages de volumes et les sélecteurs de PDB.
//   - topWL    : pod UID -> workload de tête UID.
//   - wlByName : "Kind/namespace/name" -> UID (Deployment/StatefulSet), pour les
//     cibles de HPA (scaleTargetRef).
func (s *Source) collectWorkloadExtras(ctx context.Context, pods []corev1.Pod, topWL map[string]string, wlByName map[string]string) ([]graph.Node, []graph.Edge) {
	var nodes []graph.Node
	var edges []graph.Edge
	seen := map[graph.Edge]bool{}
	id := func(uid string) graph.NodeID { return graph.NodeID{ClusterID: s.clusterID, UID: uid} }
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

	// Index des pods par namespace (sélecteurs de PDB).
	byNs := map[string][]*corev1.Pod{}
	for i := range pods {
		p := &pods[i]
		byNs[p.Namespace] = append(byNs[p.Namespace], p)
	}
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

	// --- Jobs (batch/v1) : nœud workload + Job -> CronJob via ownerReferences. ---
	if jobs, err := s.client.BatchV1().Jobs("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range jobs.Items {
			j := &jobs.Items[i]
			nodes = append(nodes, s.node(&j.ObjectMeta, "Job", graph.LayerWorkload))
			for _, ref := range j.OwnerReferences {
				add(string(j.UID), string(ref.UID), graph.EdgeOwnedBy)
			}
		}
	}

	// --- CronJobs (batch/v1) : nœud workload. ---
	if cj, err := s.client.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range cj.Items {
			nodes = append(nodes, s.node(&cj.Items[i].ObjectMeta, "CronJob", graph.LayerWorkload))
		}
	}

	// --- HPA (autoscaling/v2) : nœud config + SCALES vers la cible. ---
	if hpas, err := s.client.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range hpas.Items {
			h := &hpas.Items[i]
			nodes = append(nodes, s.node(&h.ObjectMeta, "HorizontalPodAutoscaler", graph.LayerConfig))
			ref := h.Spec.ScaleTargetRef
			if tgt := wlByName[ref.Kind+"/"+h.Namespace+"/"+ref.Name]; tgt != "" {
				add(string(h.UID), tgt, graph.EdgeScales)
			}
		}
	}

	// --- PersistentVolume (cluster-scoped) d'abord : index nom -> UID. ---
	pvUID := map[string]string{} // name -> UID
	if pvs, err := s.client.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{}); err == nil {
		for i := range pvs.Items {
			pv := &pvs.Items[i]
			nodes = append(nodes, s.node(&pv.ObjectMeta, "PersistentVolume", graph.LayerStorage))
			pvUID[pv.Name] = string(pv.UID)
		}
	}

	// --- PersistentVolumeClaim : nœud storage + PVC -> PV (via spec.volumeName). ---
	pvcUID := map[string]string{} // "namespace/name" -> UID
	if pvcs, err := s.client.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range pvcs.Items {
			pc := &pvcs.Items[i]
			nodes = append(nodes, s.node(&pc.ObjectMeta, "PersistentVolumeClaim", graph.LayerStorage))
			pvcUID[pc.Namespace+"/"+pc.Name] = string(pc.UID)
			if uid := pvUID[pc.Spec.VolumeName]; uid != "" {
				add(string(pc.UID), uid, graph.EdgeUses)
			}
		}
	}

	// --- Montages : workload -> PVC (via les volumes des pods). ---
	for i := range pods {
		p := &pods[i]
		wl := topWL[string(p.UID)]
		if wl == "" {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim == nil {
				continue
			}
			if uid := pvcUID[p.Namespace+"/"+v.PersistentVolumeClaim.ClaimName]; uid != "" {
				add(wl, uid, graph.EdgeUses)
			}
		}
	}

	// --- PodDisruptionBudget (policy/v1) : nœud sécu + PDB -> workloads couverts. ---
	if pdbs, err := s.client.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range pdbs.Items {
			pb := &pdbs.Items[i]
			nodes = append(nodes, s.node(&pb.ObjectMeta, "PodDisruptionBudget", graph.LayerSecurity))
			if pb.Spec.Selector == nil {
				continue
			}
			sel, err := metav1.LabelSelectorAsSelector(pb.Spec.Selector)
			if err != nil {
				continue
			}
			for wl := range matchWorkloads(pb.Namespace, sel) {
				add(string(pb.UID), wl, graph.EdgeSelects)
			}
		}
	}

	return nodes, edges
}
