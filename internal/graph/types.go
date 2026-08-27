// Package graph définit le modèle de données central : les nœuds et les arêtes
// du graphe de ressources. Ce modèle est indépendant de la source (live API,
// Git, ...) : n'importe quelle Source produit ces mêmes types.
package graph

// Origin indique d'où vient l'information portée par un nœud ou une arête.
//   - observed : lu depuis un cluster réel (état réel).
//   - declared : lu depuis du Git / des manifestes (état déclaré).
//
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
	LayerConfig     Layer = "config"     // ConfigMap, Secret, HPA...
	LayerSecurity   Layer = "security"   // ServiceAccount, RBAC, NetworkPolicy, PDB...
	LayerStorage    Layer = "storage"    // PersistentVolumeClaim, PersistentVolume...
	LayerInfra      Layer = "infra"      // Node (worker)...
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

	// NoSelector ne concerne que les Services : vrai si spec.selector est vide
	// (kubernetes, ExternalName, headless à endpoints externes). Un tel service
	// n'a pas de pods par conception → ne pas le marquer "cassé".
	NoSelector bool

	// IP : pod IP (status.podIP) ou ClusterIP du service. Sert à résoudre les
	// flux observés (conntrack) en nœuds. Vide si sans IP routable.
	IP string

	// Drift GitOps (déclaré vs observé), rempli seulement si une source déclarée
	// est fournie : "" (non jugé), "insync", "missing" (déclaré non déployé),
	// "unmanaged" (déployé hors Git).
	Drift string
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
	EdgeTalksTo  EdgeType = "TALKS_TO" // Trafic RÉEL observé (conntrack/eBPF) : src -> dst

	// Marqueurs d'isolation : une NetworkPolicy « protège » un workload dans un
	// sens donné (Ingress/Egress). Sert à ne juger la dérive QUE sur les
	// workloads réellement isolés (un « allow-all » ne protège pas).
	EdgeProtectsIn  EdgeType = "PROTECTS_IN"  // NetworkPolicy -> workload isolé en ENTRÉE
	EdgeProtectsOut EdgeType = "PROTECTS_OUT" // NetworkPolicy -> workload isolé en SORTIE

	// Accès & identité (qui tourne comme quoi, et ce que ça peut faire) :
	EdgeRunsOn     EdgeType = "RUNS_ON"    // Pod -> Node (spec.nodeName) : placement sur un worker
	EdgeRunsAs     EdgeType = "RUNS_AS"    // Workload -> ServiceAccount (spec.serviceAccountName)
	EdgeGrants     EdgeType = "GRANTS"     // ServiceAccount -> Role/ClusterRole (via un binding)
	EdgeReferences EdgeType = "REFERENCES" // Workload -> Secret référencé (NOM seul, jamais la valeur)
)

// Edge est une relation dirigée entre deux nœuds.
type Edge struct {
	From NodeID
	To   NodeID
	Type EdgeType
}

// Severity classe la gravité d'un point d'attention sécurité. Ordre croissant.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Finding est un POINT D'ATTENTION sécurité (pas un correctif) : il informe et
// prévient. Il pointe un nœud (et parfois une relation Node->Peer) et cite sa
// source (CIS/NIST/MITRE). La gravité pilote le dégradé jaune→orange→rouge.
type Finding struct {
	ID       string   // identifiant stable (catégorie + cible)
	Severity Severity //
	Category string   // rbac | pod | exposure | network
	Title    string   // libellé court
	Why      string   // le RISQUE, expliqué (pourquoi c'est un point d'attention)
	Ref      string   // référence (standard) vérifiable
	Node     NodeID   // nœud principal concerné
	Peer     *NodeID  // si présent : la relation Node->Peer est concernée
}
