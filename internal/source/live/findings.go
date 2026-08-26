// Moteur de « points d'attention » sécurité (DevSecOps) : il INFORME, il ne
// corrige pas. Chaque finding pointe un nœud (et parfois une relation) et cite
// sa source (CIS/NIST/MITRE). La gravité pilote le dégradé jaune→orange→rouge.
//
// Périmètre backend (structurel, calculé à la collecte) :
//   - Durcissement pod : privileged, hostNetwork/hostPID, hostPath, root, caps…
//   - RBAC / escalation : rules dangereuses des Role/ClusterRole liés à un SA
//     RÉELLEMENT utilisé par un workload.
//   - Exposition : Service LoadBalancer/NodePort, workload atteignable via Ingress.
//
// Le volet RÉSEAU / mouvement latéral (dérive du trafic observé) est calculé
// côté front, car il dépend du trafic TALKS_TO live (conntrack), absent ici.
//
// SÉCURITÉ : lecture seule, aucune valeur de secret lue.
package live

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubegraph/internal/graph"
)

func sevRank(s graph.Severity) int {
	switch s {
	case graph.SevCritical:
		return 4
	case graph.SevHigh:
		return 3
	case graph.SevMedium:
		return 2
	case graph.SevLow:
		return 1
	case graph.SevInfo:
		return 0
	}
	return -1
}

func labelsMatch(sel, lab map[string]string) bool {
	for k, v := range sel {
		if lab[k] != v {
			return false
		}
	}
	return true
}

// computeFindings produit les findings structurels à partir des objets collectés
// (+ une lecture RBAC dédiée). topWL : pod UID -> workload de tête UID.
func (s *Source) computeFindings(ctx context.Context, pods []corev1.Pod, services []corev1.Service, ingresses []networkingv1.Ingress, topWL map[string]string) []graph.Finding {
	var out []graph.Finding
	nid := func(uid string) graph.NodeID { return graph.NodeID{ClusterID: s.clusterID, UID: uid} }
	seen := map[string]bool{}
	emit := func(id string, sev graph.Severity, cat, title, why, ref string, node graph.NodeID, peer *graph.NodeID) {
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, graph.Finding{ID: id, Severity: sev, Category: cat, Title: title, Why: why, Ref: ref, Node: node, Peer: peer})
	}
	anchor := func(p *corev1.Pod) graph.NodeID {
		if w := topWL[string(p.UID)]; w != "" {
			return nid(w)
		}
		return nid(string(p.UID))
	}

	// ---------- DURCISSEMENT POD ----------
	for i := range pods {
		p := &pods[i]
		a := anchor(p)
		key := func(rule string) string { return "pod/" + a.UID + "/" + rule }
		ps := p.Spec
		if ps.HostNetwork {
			emit(key("hostnet"), graph.SevHigh, "pod", "hostNetwork activé", "Le pod partage la pile réseau du nœud : il voit le trafic local et contourne les NetworkPolicies.", "CIS Kubernetes Benchmark §5.2.4", a, nil)
		}
		if ps.HostPID {
			emit(key("hostpid"), graph.SevHigh, "pod", "hostPID activé", "Le pod voit et peut cibler les process de l'hôte (évasion de conteneur facilitée).", "CIS Kubernetes Benchmark §5.2.3", a, nil)
		}
		if ps.HostIPC {
			emit(key("hostipc"), graph.SevMedium, "pod", "hostIPC activé", "Le pod partage l'espace IPC de l'hôte.", "CIS Kubernetes Benchmark §5.2.3", a, nil)
		}
		for _, v := range ps.Volumes {
			if v.HostPath != nil {
				emit(key("hostpath"), graph.SevHigh, "pod", "Montage hostPath", fmt.Sprintf("Monte un chemin de l'hôte (%s) : accès au filesystem du nœud, évasion possible.", v.HostPath.Path), "CIS Kubernetes Benchmark §5.2.9 ; NIST SP 800-190", a, nil)
				break
			}
		}
		chk := func(c *corev1.Container) {
			// Image mutable : tag :latest ou absence de tag (non reproductible, supply-chain).
			img := c.Image
			if at := strings.LastIndex(img, "@"); at < 0 { // pas d'ancrage par digest
				last := img
				if sl := strings.LastIndex(img, "/"); sl >= 0 {
					last = img[sl+1:]
				}
				if !strings.Contains(last, ":") || strings.HasSuffix(img, ":latest") {
					emit(key("img"), graph.SevLow, "pod", "Image mutable (:latest / sans tag)", "L'image n'est pas épinglée (tag :latest ou absent, pas de digest) : build non reproductible, risque supply-chain.", "NIST SP 800-190 §3.1 ; CIS Kubernetes Benchmark §5.5", a, nil)
				}
			}
			// Pas de limites de ressources : voisin bruyant / épuisement (DoS).
			lim := c.Resources.Limits
			if lim == nil || (lim.Cpu().IsZero() && lim.Memory().IsZero()) {
				emit(key("nolimit"), graph.SevLow, "pod", "Pas de limites de ressources", "Aucune limite CPU/mémoire : un conteneur compromis ou buggé peut épuiser le nœud (déni de service).", "CIS Kubernetes Benchmark §5.7 ; NIST SP 800-190", a, nil)
			}
			for _, port := range c.Ports {
				if port.HostPort != 0 {
					emit(key("hostport"), graph.SevMedium, "pod", fmt.Sprintf("hostPort exposé (%d)", port.HostPort), "Le conteneur réserve un port sur le nœud lui-même : contourne les Services/NetworkPolicies et expose directement l'hôte.", "CIS Kubernetes Benchmark §5.2.4", a, nil)
					break
				}
			}
			sc := c.SecurityContext
			if sc == nil {
				return
			}
			if sc.Privileged != nil && *sc.Privileged {
				emit(key("priv"), graph.SevCritical, "pod", "Conteneur privileged", "Un conteneur privileged a tous les droits sur le nœud : équivalent root sur l'hôte.", "CIS Kubernetes Benchmark §5.2.1 ; MITRE ATT&CK Containers T1611", a, nil)
			}
			if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
				emit(key("pesc"), graph.SevMedium, "pod", "allowPrivilegeEscalation=true", "Le process peut gagner plus de privilèges que son parent (binaire setuid).", "CIS Kubernetes Benchmark §5.2.5", a, nil)
			}
			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				emit(key("rwfs"), graph.SevLow, "pod", "Filesystem racine inscriptible", "readOnlyRootFilesystem n'est pas activé : un attaquant peut écrire dans le conteneur (persistance, dépose d'outils).", "CIS Kubernetes Benchmark §5.2.12", a, nil)
			}
			if sc.Capabilities != nil {
				for _, c2 := range sc.Capabilities.Add {
					switch string(c2) {
					case "ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT", "DAC_READ_SEARCH", "DAC_OVERRIDE", "BPF", "PERFMON":
						emit(key("cap"), graph.SevHigh, "pod", "Capability dangereuse ("+string(c2)+")", "Cette capability étend fortement les droits du conteneur (proche d'un accès hôte).", "CIS Kubernetes Benchmark §5.2.8-9", a, nil)
					}
				}
			}
		}
		for j := range ps.InitContainers {
			chk(&ps.InitContainers[j])
		}
		for j := range ps.Containers {
			chk(&ps.Containers[j])
		}
		// Tourne en root ? (aucun runAsNonRoot / runAsUser non nul, ni au pod ni aux conteneurs)
		root := true
		if ps.SecurityContext != nil {
			if ps.SecurityContext.RunAsNonRoot != nil && *ps.SecurityContext.RunAsNonRoot {
				root = false
			}
			if ps.SecurityContext.RunAsUser != nil && *ps.SecurityContext.RunAsUser != 0 {
				root = false
			}
		}
		for j := range ps.Containers {
			sc := ps.Containers[j].SecurityContext
			if sc != nil && ((sc.RunAsNonRoot != nil && *sc.RunAsNonRoot) || (sc.RunAsUser != nil && *sc.RunAsUser != 0)) {
				root = false
			}
		}
		if root {
			emit(key("root"), graph.SevMedium, "pod", "Tourne en root (probable)", "Aucun runAsNonRoot / runAsUser non-root : le conteneur tourne probablement en root.", "CIS Kubernetes Benchmark §5.2.6 ; NIST SP 800-190", a, nil)
		}
		if (ps.ServiceAccountName == "" || ps.ServiceAccountName == "default") && (ps.AutomountServiceAccountToken == nil || *ps.AutomountServiceAccountToken) {
			emit(key("defsa"), graph.SevLow, "pod", "SA 'default' + token monté", "Tourne sous le ServiceAccount 'default' avec son token monté : identité partagée, moindre privilège non respecté.", "CIS Kubernetes Benchmark §5.1.5-5.1.6", a, nil)
		}
		if ps.ShareProcessNamespace != nil && *ps.ShareProcessNamespace {
			emit(key("shareproc"), graph.SevMedium, "pod", "shareProcessNamespace activé", "Les conteneurs du pod partagent leurs process : un conteneur compromis voit et cible les autres.", "NIST SP 800-190", a, nil)
		}
		// Pas de profil seccomp (ni au pod, ni sur un conteneur) : aucun filtrage d'appels système.
		seccomp := ps.SecurityContext != nil && ps.SecurityContext.SeccompProfile != nil
		for j := range ps.Containers {
			if sc := ps.Containers[j].SecurityContext; sc != nil && sc.SeccompProfile != nil {
				seccomp = true
			}
		}
		if !seccomp {
			emit(key("seccomp"), graph.SevLow, "pod", "Pas de profil seccomp", "Aucun seccompProfile : les appels système ne sont pas filtrés, la surface noyau est maximale.", "CIS Kubernetes Benchmark §5.7.2 ; NIST SP 800-190", a, nil)
		}
	}

	// ---------- EXPOSITION ----------
	svcUID := map[string]string{}
	svcByUID := map[string]*corev1.Service{}
	for i := range services {
		sv := &services[i]
		svcUID[sv.Namespace+"/"+sv.Name] = string(sv.UID)
		svcByUID[string(sv.UID)] = sv
		if t := sv.Spec.Type; t == corev1.ServiceTypeLoadBalancer || t == corev1.ServiceTypeNodePort {
			emit("exp/svc/"+string(sv.UID), graph.SevMedium, "exposure", "Service "+string(t), "Ce service est atteignable hors du cluster ("+string(t)+") : surface d'attaque exposée.", "NIST SP 800-190 §3.3", nid(string(sv.UID)), nil)
		}
		if len(sv.Spec.ExternalIPs) > 0 {
			emit("exp/eip/"+string(sv.UID), graph.SevMedium, "exposure", "Service avec externalIPs", "Le service publie des externalIPs : trafic routé vers le pod depuis l'extérieur, hors des contrôles habituels.", "NIST SP 800-190 §3.3", nid(string(sv.UID)), nil)
		}
	}
	podsByNs := map[string][]*corev1.Pod{}
	for i := range pods {
		podsByNs[pods[i].Namespace] = append(podsByNs[pods[i].Namespace], &pods[i])
	}
	for i := range ingresses {
		ing := &ingresses[i]
		noTLS := len(ing.Spec.TLS) == 0
		names := map[string]bool{}
		if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
			names[ing.Spec.DefaultBackend.Service.Name] = true
		}
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, pth := range rule.HTTP.Paths {
				if pth.Backend.Service != nil {
					names[pth.Backend.Service.Name] = true
				}
			}
		}
		for name := range names {
			sv := svcByUID[svcUID[ing.Namespace+"/"+name]]
			if sv == nil || len(sv.Spec.Selector) == 0 {
				continue
			}
			for _, p := range podsByNs[sv.Namespace] {
				if !labelsMatch(sv.Spec.Selector, p.Labels) {
					continue
				}
				w := topWL[string(p.UID)]
				if w == "" {
					continue
				}
				emit("exp/ing/"+w, graph.SevMedium, "exposure", "Exposé via Ingress", "Ce workload est atteignable depuis l'extérieur via un Ingress ("+ing.Name+") : porte d'entrée à surveiller.", "NIST SP 800-190 §3.3", nid(w), nil)
				if noTLS {
					emit("exp/tls/"+w, graph.SevLow, "exposure", "Ingress sans TLS", "L'Ingress ("+ing.Name+") n'a pas de section TLS : trafic potentiellement en clair (interception, vol de session).", "OWASP ; CIS Kubernetes Benchmark §5.3", nid(w), nil)
				}
			}
		}
	}

	// ---------- RBAC / ESCALATION ----------
	usedSA := map[string]bool{} // "ns/name" des SA réellement utilisés par un pod
	for i := range pods {
		sa := pods[i].Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		usedSA[pods[i].Namespace+"/"+sa] = true
	}
	saUID := map[string]string{}
	if sas, err := s.client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range sas.Items {
			saUID[sas.Items[i].Namespace+"/"+sas.Items[i].Name] = string(sas.Items[i].UID)
		}
	}
	type roleInfo struct {
		uid   string
		rules []rbacv1.PolicyRule
	}
	roleByKey := map[string]roleInfo{}
	if roles, err := s.client.RbacV1().Roles("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range roles.Items {
			r := &roles.Items[i]
			roleByKey["Role/"+r.Namespace+"/"+r.Name] = roleInfo{string(r.UID), r.Rules}
		}
	}
	if croles, err := s.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{}); err == nil {
		for i := range croles.Items {
			c := &croles.Items[i]
			roleByKey["ClusterRole//"+c.Name] = roleInfo{string(c.UID), c.Rules}
		}
	}
	judge := func(saNs, saName string, ri roleInfo, cluster bool) {
		saKey := saNs + "/" + saName
		if !usedSA[saKey] { // on ne juge QUE les SA qui tournent (réduit le bruit)
			return
		}
		said := saUID[saKey]
		if said == "" {
			return
		}
		sev, title, why := rateRules(ri.rules, cluster)
		if sev == "" {
			return
		}
		peer := nid(ri.uid)
		emit("rbac/"+said+"/"+ri.uid, sev, "rbac", title, why, "CIS Kubernetes Benchmark §5.1 ; MITRE ATT&CK Containers T1548", nid(said), &peer)
	}
	if rbs, err := s.client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range rbs.Items {
			rb := &rbs.Items[i]
			key := "Role/" + rb.Namespace + "/" + rb.RoleRef.Name
			if rb.RoleRef.Kind == "ClusterRole" {
				key = "ClusterRole//" + rb.RoleRef.Name
			}
			ri, ok := roleByKey[key]
			if !ok {
				continue
			}
			for _, sub := range rb.Subjects {
				if sub.Kind != "ServiceAccount" {
					continue
				}
				ns := sub.Namespace
				if ns == "" {
					ns = rb.Namespace
				}
				judge(ns, sub.Name, ri, rb.RoleRef.Kind == "ClusterRole")
			}
		}
	}
	if crbs, err := s.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); err == nil {
		for i := range crbs.Items {
			crb := &crbs.Items[i]
			ri, ok := roleByKey["ClusterRole//"+crb.RoleRef.Name]
			if !ok {
				continue
			}
			for _, sub := range crb.Subjects {
				if sub.Kind != "ServiceAccount" || sub.Namespace == "" {
					continue
				}
				judge(sub.Namespace, sub.Name, ri, true)
			}
		}
	}

	return out
}

// rateRules évalue les règles d'un rôle et retourne la gravité la plus élevée
// détectée (vide si rien de notable). cluster=true si c'est un ClusterRole lié
// via un ClusterRoleBinding (portée cluster).
func rateRules(rules []rbacv1.PolicyRule, cluster bool) (graph.Severity, string, string) {
	has := func(list []string, want ...string) bool {
		for _, x := range list {
			for _, w := range want {
				if x == w {
					return true
				}
			}
		}
		return false
	}
	best, title, why := graph.Severity(""), "", ""
	up := func(sev graph.Severity, t, w string) {
		if sevRank(sev) > sevRank(best) {
			best, title, why = sev, t, w
		}
	}
	for _, r := range rules {
		star := has(r.Verbs, "*") && has(r.Resources, "*") && (len(r.APIGroups) == 0 || has(r.APIGroups, "*", ""))
		if star {
			if cluster {
				up(graph.SevCritical, "Rôle « tous droits » (cluster)", "ClusterRole avec verbes * sur ressources * : équivaut à cluster-admin. Sa compromission = tout le cluster.")
			} else {
				up(graph.SevHigh, "Rôle « tous droits » (namespace)", "Role avec * sur * : contrôle total du namespace.")
			}
		}
		if has(r.Resources, "secrets", "*") && has(r.Verbs, "get", "list", "watch", "*") {
			up(graph.SevHigh, "Peut lire les secrets", "get/list sur les secrets : vol de credentials et mouvement latéral possibles.")
		}
		if has(r.Resources, "pods/exec", "pods/attach") && has(r.Verbs, "create", "*") {
			up(graph.SevHigh, "Peut exec dans les pods", "create pods/exec : exécution de commandes dans d'autres pods.")
		}
		if has(r.Resources, "serviceaccounts/token") && has(r.Verbs, "create", "*") {
			up(graph.SevHigh, "Peut forger des tokens de SA", "create serviceaccounts/token : usurpation d'identité de n'importe quel ServiceAccount.")
		}
		if has(r.Verbs, "impersonate") {
			up(graph.SevHigh, "Peut usurper (impersonate)", "Le verbe impersonate permet d'agir en tant qu'un autre utilisateur / SA / groupe.")
		}
		if has(r.Resources, "roles", "clusterroles", "rolebindings", "clusterrolebindings", "*") && has(r.Verbs, "bind", "escalate", "create", "update", "patch", "*") {
			up(graph.SevHigh, "Peut modifier le RBAC", "Écriture de rôles/bindings (bind/escalate/create) : escalade de privilèges directe.")
		}
		if has(r.Resources, "pods", "deployments", "daemonsets", "*") && has(r.Verbs, "create", "*") {
			up(graph.SevMedium, "Peut créer des workloads", "create pods/deployments : peut lancer un pod privilégié pour escalader.")
		}
		if has(r.Resources, "certificatesigningrequests", "certificatesigningrequests/approval", "*") && has(r.Verbs, "create", "update", "approve", "*") {
			up(graph.SevHigh, "Peut émettre/approuver des certificats", "Contrôle des CSR : peut se forger un certificat client au nom de n'importe quelle identité (escalade).")
		}
		if has(r.Resources, "validatingwebhookconfigurations", "mutatingwebhookconfigurations", "*") && has(r.Verbs, "create", "update", "patch", "*") {
			up(graph.SevHigh, "Peut modifier l'admission control", "Écriture des webhooks d'admission : peut intercepter/altérer toute création d'objet (backdoor cluster).")
		}
		if has(r.Resources, "pods/portforward") && has(r.Verbs, "create", "*") {
			up(graph.SevMedium, "Peut port-forward vers les pods", "create pods/portforward : tunnel réseau direct vers des pods, contourne les Services.")
		}
		if has(r.Resources, "nodes", "nodes/proxy", "*") && has(r.Verbs, "get", "list", "create", "*") {
			up(graph.SevMedium, "Accès aux nœuds", "Droit sur les nodes / nodes/proxy : lecture kubelet, accès aux pods de l'hôte.")
		}
		if has(r.Resources, "*") && has(r.Verbs, "get", "list", "watch") && !has(r.Verbs, "*") {
			up(graph.SevMedium, "Lecture étendue du cluster", "get/list/watch sur * : visibilité sur toutes les ressources (reconnaissance, fuite de config).")
		}
	}
	return best, title, why
}
