// Accès & identité : « qui tourne comme quoi, et ce que ça peut faire ».
//
//   RUNS_AS     Workload -> ServiceAccount     (spec.serviceAccountName du pod)
//   GRANTS      ServiceAccount -> Role/ClusterRole (via Role/ClusterRoleBinding)
//   REFERENCES  Workload -> Secret             (NOM seul, déduit des specs)
//
// SÉCURITÉ — invariant du projet : on ne demande JAMAIS `get secrets` et on ne
// lit JAMAIS la valeur d'un secret. Les secrets référencés sont DÉDUITS des
// specs des pods (imagePullSecrets, env.secretKeyRef, envFrom.secretRef,
// volumes.secret) : seul le NOM apparaît, jamais `.data`. Les nœuds Secret sont
// donc synthétiques (pas de lecture de l'objet Secret).
//
// Les bindings (Role/ClusterRoleBinding) ne sont PAS des nœuds : on les replie
// en arêtes GRANTS du ServiceAccount vers le rôle. Les sujets non-SA (User,
// Group : des humains, pas des objets du cluster) sont ignorés — hors périmètre.
//
// Chaque lecture est NON bloquante : un groupe d'API absent (RBAC restreint…)
// fait sauter ce type sans casser le reste.
package live

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubegraph/internal/graph"
)

// collectAccess retourne les nœuds (ServiceAccount, Role, ClusterRole, Secret)
// et les arêtes RUNS_AS / GRANTS / REFERENCES.
//   - pods  : pour l'identité (serviceAccountName) et les secrets référencés.
//   - topWL : pod UID -> workload de tête UID.
func (s *Source) collectAccess(ctx context.Context, pods []corev1.Pod, topWL map[string]string) ([]graph.Node, []graph.Edge) {
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

	// --- ServiceAccounts : nœuds + index "namespace/name" -> UID. ---
	saUID := map[string]string{}
	if sas, err := s.client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range sas.Items {
			sa := &sas.Items[i]
			nodes = append(nodes, s.node(&sa.ObjectMeta, "ServiceAccount", graph.LayerSecurity))
			saUID[sa.Namespace+"/"+sa.Name] = string(sa.UID)
		}
	}

	// --- Roles / ClusterRoles : nœuds + index pour les roleRef des bindings. ---
	roleUID := map[string]string{}    // "namespace/name" -> UID
	clusterRoleUID := map[string]string{} // "name" -> UID
	if roles, err := s.client.RbacV1().Roles("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range roles.Items {
			r := &roles.Items[i]
			nodes = append(nodes, s.node(&r.ObjectMeta, "Role", graph.LayerSecurity))
			roleUID[r.Namespace+"/"+r.Name] = string(r.UID)
		}
	}
	if croles, err := s.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{}); err == nil {
		for i := range croles.Items {
			cr := &croles.Items[i]
			nodes = append(nodes, s.node(&cr.ObjectMeta, "ClusterRole", graph.LayerSecurity))
			clusterRoleUID[cr.Name] = string(cr.UID)
		}
	}

	// roleRefUID résout un roleRef de binding vers l'UID du rôle correspondant.
	roleRefUID := func(bindingNs, kind, name string) string {
		if kind == "ClusterRole" {
			return clusterRoleUID[name]
		}
		return roleUID[bindingNs+"/"+name] // Role : même namespace que le binding.
	}

	// --- RoleBindings : SA sujet -> GRANTS -> rôle (repli du binding). ---
	if rbs, err := s.client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range rbs.Items {
			rb := &rbs.Items[i]
			tgt := roleRefUID(rb.Namespace, rb.RoleRef.Kind, rb.RoleRef.Name)
			if tgt == "" {
				continue
			}
			for _, sub := range rb.Subjects {
				if sub.Kind != "ServiceAccount" {
					continue // User/Group : humains, hors périmètre.
				}
				ns := sub.Namespace
				if ns == "" {
					ns = rb.Namespace
				}
				add(saUID[ns+"/"+sub.Name], tgt, graph.EdgeGrants)
			}
		}
	}

	// --- ClusterRoleBindings : SA sujet -> GRANTS -> ClusterRole. ---
	if crbs, err := s.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); err == nil {
		for i := range crbs.Items {
			crb := &crbs.Items[i]
			tgt := clusterRoleUID[crb.RoleRef.Name]
			if tgt == "" {
				continue
			}
			for _, sub := range crb.Subjects {
				if sub.Kind != "ServiceAccount" || sub.Namespace == "" {
					continue
				}
				add(saUID[sub.Namespace+"/"+sub.Name], tgt, graph.EdgeGrants)
			}
		}
	}

	// --- Par pod (roulé au workload de tête) : identité + secrets référencés. ---
	secretSeen := map[string]bool{} // évite de recréer le même nœud Secret
	secretNode := func(ns, name string) string {
		if name == "" {
			return ""
		}
		uid := "secret/" + ns + "/" + name // synthétique : AUCUNE lecture de l'objet.
		if !secretSeen[uid] {
			secretSeen[uid] = true
			nodes = append(nodes, graph.Node{
				ID: id(uid), Kind: "Secret", Namespace: ns, Name: name,
				Layer: graph.LayerSecurity, Origin: graph.OriginObserved,
			})
		}
		return uid
	}

	for i := range pods {
		p := &pods[i]
		wl := topWL[string(p.UID)]
		if wl == "" {
			continue
		}
		// Identité : Workload -> ServiceAccount.
		saName := p.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		if uid := saUID[p.Namespace+"/"+saName]; uid != "" {
			add(wl, uid, graph.EdgeRunsAs)
		}
		// Secrets référencés (NOM seul) : imagePullSecrets, env, envFrom, volumes.
		for _, ips := range p.Spec.ImagePullSecrets {
			add(wl, secretNode(p.Namespace, ips.Name), graph.EdgeReferences)
		}
		for _, v := range p.Spec.Volumes {
			if v.Secret != nil {
				add(wl, secretNode(p.Namespace, v.Secret.SecretName), graph.EdgeReferences)
			}
		}
		allContainers := func(f func(c *corev1.Container)) {
			for j := range p.Spec.InitContainers {
				f(&p.Spec.InitContainers[j])
			}
			for j := range p.Spec.Containers {
				f(&p.Spec.Containers[j])
			}
		}
		allContainers(func(c *corev1.Container) {
			for _, e := range c.Env {
				if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
					add(wl, secretNode(p.Namespace, e.ValueFrom.SecretKeyRef.Name), graph.EdgeReferences)
				}
			}
			for _, ef := range c.EnvFrom {
				if ef.SecretRef != nil {
					add(wl, secretNode(p.Namespace, ef.SecretRef.Name), graph.EdgeReferences)
				}
			}
		})
	}

	return nodes, edges
}
