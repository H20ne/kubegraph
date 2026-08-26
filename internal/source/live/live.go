// Package live implémente Source en lisant un cluster Kubernetes réel via
// client-go. C'est la source "observed" : ce qui tourne vraiment.
//
// MVP : liste les 5 kinds de la Phase 1 et les transforme en nœuds. Les arêtes
// (resolvers) arrivent à l'étape 3 et se brancheront ici sans casser l'API.
package live

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"kubegraph/internal/graph"
	"kubegraph/internal/resolve"
)

// Source lit un cluster réel. Elle ne fait QUE de la lecture.
type Source struct {
	clusterID string
	client    kubernetes.Interface
	dyn       dynamic.Interface // pour les CRD (KEDA…) ; peut être nil
}

// New construit une Source live à partir d'un kubeconfig.
//   - kubeconfigPath vide => règles de chargement par défaut (env KUBECONFIG,
//     ~/.kube/config), avec repli sur la config in-cluster.
//   - clusterID vide => nom du contexte courant du kubeconfig.
func New(kubeconfigPath, clusterID string) (*Source, error) {
	cfg, ctxName, err := loadConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("création du client kubernetes : %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("création du client dynamique : %w", err)
	}
	if clusterID == "" {
		clusterID = ctxName
	}
	return &Source{clusterID: clusterID, client: client, dyn: dyn}, nil
}

// NewWithClient injecte un client (utilisé par les tests avec le fake client).
func NewWithClient(client kubernetes.Interface, clusterID string) *Source {
	return &Source{clusterID: clusterID, client: client}
}

// NewWithClients injecte les deux clients (tests couvrant les CRD comme KEDA).
func NewWithClients(client kubernetes.Interface, dyn dynamic.Interface, clusterID string) *Source {
	return &Source{clusterID: clusterID, client: client, dyn: dyn}
}

// ClusterID satisfait source.Source.
func (s *Source) ClusterID() string { return s.clusterID }

// Collect liste les 5 kinds du MVP, les convertit en nœuds, puis calcule les
// arêtes via le package resolve (partagé avec les futures sources).
func (s *Source) Collect(ctx context.Context) ([]graph.Node, []graph.Edge, error) {
	opts := metav1.ListOptions{}

	deployments, err := s.client.AppsV1().Deployments("").List(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("liste des deployments : %w", err)
	}
	replicaSets, err := s.client.AppsV1().ReplicaSets("").List(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("liste des replicasets : %w", err)
	}
	pods, err := s.client.CoreV1().Pods("").List(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("liste des pods : %w", err)
	}
	services, err := s.client.CoreV1().Services("").List(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("liste des services : %w", err)
	}
	ingresses, err := s.client.NetworkingV1().Ingresses("").List(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("liste des ingresses : %w", err)
	}
	statefulSets, err := s.client.AppsV1().StatefulSets("").List(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("liste des statefulsets : %w", err)
	}
	daemonSets, err := s.client.AppsV1().DaemonSets("").List(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("liste des daemonsets : %w", err)
	}

	var nodes []graph.Node
	for i := range deployments.Items {
		nodes = append(nodes, s.node(&deployments.Items[i].ObjectMeta, "Deployment", graph.LayerWorkload))
	}
	for i := range statefulSets.Items {
		nodes = append(nodes, s.node(&statefulSets.Items[i].ObjectMeta, "StatefulSet", graph.LayerWorkload))
	}
	for i := range daemonSets.Items {
		nodes = append(nodes, s.node(&daemonSets.Items[i].ObjectMeta, "DaemonSet", graph.LayerWorkload))
	}
	for i := range replicaSets.Items {
		nodes = append(nodes, s.node(&replicaSets.Items[i].ObjectMeta, "ReplicaSet", graph.LayerWorkload))
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		n := s.node(&p.ObjectMeta, "Pod", graph.LayerWorkload)
		n.IP = p.Status.PodIP // pour résoudre les flux observés
		nodes = append(nodes, n)
	}
	for i := range services.Items {
		sv := &services.Items[i]
		n := s.node(&sv.ObjectMeta, "Service", graph.LayerNetworking)
		n.NoSelector = len(sv.Spec.Selector) == 0
		if sv.Spec.ClusterIP != "" && sv.Spec.ClusterIP != "None" {
			n.IP = sv.Spec.ClusterIP
		}
		nodes = append(nodes, n)
	}
	for i := range ingresses.Items {
		nodes = append(nodes, s.node(&ingresses.Items[i].ObjectMeta, "Ingress", graph.LayerNetworking))
	}

	edges := resolve.Edges(s.clusterID, resolve.Objects{
		Deployments: deployments.Items,
		ReplicaSets: replicaSets.Items,
		Pods:        pods.Items,
		Services:    services.Items,
		Ingresses:   ingresses.Items,
	})

	// Index (namespace/name -> uid) pour rattacher les dépendances cross-namespace.
	deployUID := make(map[string]string, len(deployments.Items))
	for i := range deployments.Items {
		d := &deployments.Items[i]
		deployUID[d.Namespace+"/"+d.Name] = string(d.UID)
	}
	svcUID := make(map[string]string, len(services.Items))
	for i := range services.Items {
		sv := &services.Items[i]
		svcUID[sv.Namespace+"/"+sv.Name] = string(sv.UID)
	}

	// KEDA (CRD) : ScaledObject -> Deployment, et Service déclencheur -> ScaledObject.
	if kn, ke := s.collectKeda(ctx, deployUID, svcUID); kn != nil {
		nodes = append(nodes, kn...)
		edges = append(edges, ke...)
	}

	// Dépendances par config : workload -> service appelé (USES), déduites de
	// env / args / command / ConfigMaps.
	edges = append(edges, s.collectConfigDeps(ctx, deployments, statefulSets, daemonSets, services)...)

	// NetworkPolicy -> arêtes ALLOWS (base déclarée pour la détection de dérive).
	topWL := topWorkloadMap(deployments.Items, statefulSets.Items, daemonSets.Items, replicaSets.Items, pods.Items)
	np, ne := s.collectNetpol(ctx, pods.Items, topWL, s.namespaceLabels(ctx))
	nodes = append(nodes, np...)
	edges = append(edges, ne...)

	// Ressources complémentaires : Jobs, CronJobs, HPA, PVC/PV, PDB.
	// Index "Kind/namespace/name" -> UID pour les cibles de HPA (scaleTargetRef).
	wlByName := map[string]string{}
	for i := range deployments.Items {
		d := &deployments.Items[i]
		wlByName["Deployment/"+d.Namespace+"/"+d.Name] = string(d.UID)
	}
	for i := range statefulSets.Items {
		st := &statefulSets.Items[i]
		wlByName["StatefulSet/"+st.Namespace+"/"+st.Name] = string(st.UID)
	}
	xn, xe := s.collectWorkloadExtras(ctx, pods.Items, topWL, wlByName)
	nodes = append(nodes, xn...)
	edges = append(edges, xe...)

	// Accès & identité : ServiceAccount, Role/ClusterRole (bindings repliés en
	// GRANTS), et secrets RÉFÉRENCÉS (noms déduits des specs, jamais les valeurs).
	an, ae := s.collectAccess(ctx, pods.Items, topWL)
	nodes = append(nodes, an...)
	edges = append(edges, ae...)

	return nodes, edges, nil
}

// topWorkloadMap construit : UID de pod -> UID de son workload de tête
// (Deployment/StatefulSet/DaemonSet), en remontant les ownerReferences
// contrôleurs (le ReplicaSet intermédiaire d'un Deployment est traversé).
func topWorkloadMap(deps []appsv1.Deployment, sts []appsv1.StatefulSet, ds []appsv1.DaemonSet, rs []appsv1.ReplicaSet, pods []corev1.Pod) map[string]string {
	owner := map[string]string{} // enfant UID -> contrôleur UID
	kindByUID := map[string]string{}
	for i := range deps {
		kindByUID[string(deps[i].UID)] = "Deployment"
	}
	for i := range sts {
		kindByUID[string(sts[i].UID)] = "StatefulSet"
	}
	for i := range ds {
		kindByUID[string(ds[i].UID)] = "DaemonSet"
	}
	for i := range rs {
		r := &rs[i]
		kindByUID[string(r.UID)] = "ReplicaSet"
		if c := metav1.GetControllerOf(r); c != nil {
			owner[string(r.UID)] = string(c.UID)
		}
	}
	isWL := func(k string) bool { return k == "Deployment" || k == "StatefulSet" || k == "DaemonSet" }
	out := make(map[string]string, len(pods))
	for i := range pods {
		c := metav1.GetControllerOf(&pods[i])
		if c == nil {
			continue
		}
		cur := string(c.UID)
		for g := 0; g < 12 && cur != ""; g++ {
			if isWL(kindByUID[cur]) {
				out[string(pods[i].UID)] = cur
				break
			}
			cur = owner[cur]
		}
	}
	return out
}

// namespaceLabels retourne : nom de namespace -> ses labels (pour les
// namespaceSelector des NetworkPolicies). Non bloquant si non accessible.
func (s *Source) namespaceLabels(ctx context.Context) map[string]labels.Set {
	out := map[string]labels.Set{}
	nss, err := s.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return out
	}
	for i := range nss.Items {
		out[nss.Items[i].Name] = labels.Set(nss.Items[i].Labels)
	}
	return out
}

// node mappe un ObjectMeta Kubernetes vers un nœud du graphe.
func (s *Source) node(m *metav1.ObjectMeta, kind string, layer graph.Layer) graph.Node {
	return graph.Node{
		ID:        graph.NodeID{ClusterID: s.clusterID, UID: string(m.UID)},
		Kind:      kind,
		Namespace: m.Namespace,
		Name:      m.Name,
		Labels:    m.Labels,
		Layer:     layer,
		Origin:    graph.OriginObserved,
	}
}

// loadConfig charge la config client : kubeconfig d'abord, repli in-cluster.
// Retourne aussi le nom du contexte courant (sert de clusterID par défaut).
func loadConfig(path string) (*rest.Config, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		rules.ExplicitPath = path
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})

	cfg, err := cc.ClientConfig()
	if err != nil {
		// Repli : on tourne peut-être dans un pod (cas de l'agent hub-spoke).
		if inCluster, icErr := rest.InClusterConfig(); icErr == nil {
			return inCluster, "in-cluster", nil
		}
		return nil, "", fmt.Errorf("chargement du kubeconfig : %w", err)
	}

	ctxName := "unknown"
	if raw, rErr := cc.RawConfig(); rErr == nil && raw.CurrentContext != "" {
		ctxName = raw.CurrentContext
	}
	return cfg, ctxName, nil
}
