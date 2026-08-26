// Package graph définit le modèle de données central : les nœuds et les arêtes
// du graphe de ressources. Ce modèle est indépendant de la source (live API,
// Git, ...) : n'importe quelle Source produit ces mêmes types.
package graph

// Origin indique d'où vient l'information portée par un nœud ou une arête.
//   - observed : lu depuis un cluster réel (état réel).
//   - declared : lu depuis du Git / des manifestes (état déclaré).
// Croiser les deux permettra plus tard la détection de drift.
type Origin string

const (
	OriginObserved Origin = "observed"
	OriginDeclared Origin = "declared"
)

// Layer classe un nœud par couche fonctionnelle. Sert de code couleur dans
// le rendu (un cercle de l'ego-graph).
type Layer string

const (
	LayerWorkload   Layer = "workload"   // Deployment, ReplicaSet, Pod...
	LayerNetworking Layer = "networking" // Service, Ingress...
	LayerConfig     Layer = "config"     // ConfigMap, Secret...
	LayerSecurity   Layer = "security"   // ServiceAccount, RBAC, NetworkPolicy...
	LayerUnknown    Layer = "unknown"
)

// NodeID identifie un nœud de façon unique.
//
// PIÈGE : metadata.uid n'est unique QUE dans un cluster. En multi-cluster,
// deux objets de clusters différents peuvent partager le même UID. On préfixe
// donc toujours par ClusterID.
type NodeID struct {
	ClusterID string // identifiant du cluster (défini par la Source)
	UID       string // metadata.uid, unique au sein du cluster
}

// Node représente un objet Kubernetes dans le graphe.
type Node struct {
	ID        NodeID
	Kind      string            // Deployment, Pod, Service...
	Namespace string            // vide pour les objets cluster-scoped
	Name      string            // metadata.name
	Labels    map[string]string // metadata.labels
	Layer     Layer             // couche fonctionnelle (couleur du cercle)
	Origin    Origin            // observed | declared
}

// EdgeType énumère les relations reconnues entre nœuds. On démarre le MVP avec
// trois arêtes explicites ; les arêtes implicites (RBAC, NetworkPolicy) et les
// findings sécu viendront plus tard sans changer ce modèle.
type EdgeType string

const (
	EdgeOwnedBy  EdgeType = "OWNED_BY"  // Pod -> ReplicaSet -> Deployment (ownerReferences)
	EdgeSelects  EdgeType = "SELECTS"   // Service -> Pod (matching de labels)
	EdgeRoutesTo EdgeType = "ROUTES_TO" // Ingress -> Service (rules.backend.service)

	// Dépendances au-delà du câblage standard (souvent cross-namespace) :
	EdgeScales   EdgeType = "SCALES"   // ScaledObject (KEDA) -> Deployment (scaleTargetRef)
	EdgeTriggers EdgeType = "TRIGGERS" // Service source (ex: Kafka) -> ScaledObject (trigger KEDA)
	EdgeUses     EdgeType = "USES"     // Workload -> Service référencé dans sa config (env/ConfigMap)
	EdgeAllows   EdgeType = "ALLOWS"   // NetworkPolicy : connectivité autorisée (déclarée, pas observée)
)

// Edge est une relation dirigée entre deux nœuds.
type Edge struct {
	From NodeID
	To   NodeID
	Type EdgeType
}
