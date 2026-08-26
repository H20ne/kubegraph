# kubegraph

Outil de cartographie relationnelle d'un cluster Kubernetes. On clique un nœud,
il déplie ses corrélations en cercles concentriques (ego-graph), pour aider à
trouver **où sont les choses** et **qui a accès à quoi**.

## État : MVP en construction (Phase 1)

Architecture cible : multi-cluster **hub-spoke**, vision **DevSecOps** (findings
rattachés au graphe). Voir la roadmap pour les phases.

## Principe d'architecture

Le moteur ne connaît qu'une interface `Source`. Le live cluster, le Git (GitOps)
et l'agent hub-spoke l'implémentent tous → aucun code moteur à réécrire pour
ajouter une source.

```
Source (live | git | agent)  ->  Relationship engine  ->  Graph store  ->  API  ->  Frontend (Cytoscape.js)
```

## Arborescence

```
cmd/kubegraph/      point d'entrée (hub)
internal/graph/     modèle central : Node, Edge, types d'arêtes
internal/source/    contrat Source (implémenté par chaque source de données)
```

## Arborescence (suite)

```
internal/resolve/   resolvers d'arêtes (partagés entre sources)
internal/store/     graphe en mémoire + ego-query (BFS)
internal/api/       serveur HTTP (/nodes, /ego, /healthz)
web/index.html      frontend Cytoscape.js (fichier autonome)
```

## Lancer

1. Backend (a besoin d'un kubeconfig vers un cluster) :

```sh
go build ./...
KUBECONFIG=~/.kube/config go run ./cmd/kubegraph   # écoute sur :8080
```

2. Frontend : ouvrir `web/index.html` dans le navigateur. Il tape l'API
   (`http://localhost:8080` par défaut), propose un nœud de départ, et déplie
   un cercle à chaque clic.

## API

- `GET /nodes` — liste des nœuds (pour choisir un point de départ).
- `GET /ego?cluster=<id>&uid=<uid>&depth=<n>` — sous-graphe autour d'un nœud.
- `GET /healthz` — sonde de vie.

## Déploiement (RBAC lecture seule)

```sh
kubectl apply -f deploy/rbac.yaml
```

Crée le namespace `kubegraph`, un ServiceAccount, et un ClusterRole
`get`/`list`/`watch` sur les 5 kinds — rien d'autre. Vérifier les droits :

```sh
kubectl auth can-i --list --as=system:serviceaccount:kubegraph:kubegraph
# create/update/delete sur ces ressources doivent renvoyer "no"
```

Le code n'appelle que `List` : aucun verbe d'écriture, garanti par lecture des
sources (`grep -rnE '\.(Create|Update|Patch|Delete)\(' internal/`).

## Tests

```sh
go test ./...
```

## Sécurité

L'outil est **lecture seule**. Le ServiceAccount ne demande que `get`/`list`/
`watch`. Aucun write sur le cluster, jamais.
