# kubegraph — suivi des tâches (roadmap)

Légende : ✅ fait · 🔜 prochain · ⏳ planifié · 🧊 en réserve · ❌ écarté

---

## Livré

- ✅ Modèle central source-agnostique (`Node`, `Edge`, `Source`) — multi-cluster par `ClusterID`.
- ✅ Source live : workloads, Pods, Services, Ingress, OWNED_BY/SELECTS/ROUTES_TO.
- ✅ Workloads étendus : Jobs, CronJobs, HPA (SCALES), PVC/PV (USES), PDB.
- ✅ Réseau : NetworkPolicy (ALLOWS + PROTECTS_IN/OUT), agent conntrack (TALKS_TO).
- ✅ Accès & identité : ServiceAccount (RUNS_AS), RBAC (GRANTS), Secrets par nom (REFERENCES) — jamais de valeur lue.
- ✅ Sécurité : moteur de findings (CIS/NIST/MITRE/OWASP), onglet dédié + overlay « mode sécu ».
- ✅ GitOps : dérive déclaré vs observé (présence) depuis un dossier de YAML rendus ; `run.sh --git-snapshot` ; lecteur qui déroule les `List`.
- ✅ UI : Sankey premium, pan/zoom/fit, surbrillance de bout en bout, onglet Explorer refondu (cartes + connecteurs orthogonaux + flux animé + panneau passeport).

---

## ✅ ① Filtre d'affichage par type
**Livré** : barre de chips « afficher » par catégorie (Workloads, Pods, Services, Ingress, Config, Stockage… + Sécurité/Autoscaling/Nodes dans Explorer).
- Catégorie masquée = nœud **et** arêtes retirés (pas de reroutage auto).
- Appliqué à **Exécution** (gate placement + liens) et **Explorer** (`cy` show/hide, non destructif). Réseau garde son `masquer l'infra`.
- État persisté en `localStorage` (`kubegraph_hidden_cats`).
- Vérifié : Exécution masque la colonne Dépendances quand Config+Stockage off ; Explorer met SA/Role en `display:none` quand Sécurité off ; aucune régression Sécurité/Sankey.

## ✅ ③a Collecte des Nodes (workers) + placement
**Livré** :
- Kind `Node` (couche `infra`, couleur ambre, icône rack) + arête `RUNS_ON` (Pod → Node) via `pod.spec.nodeName` — `internal/source/live/nodes.go`.
- IP interne du node captée (résolution de flux + futur ④). Non bloquant si RBAC `nodes` absent.
- RBAC : ajout `nodes` (get/list/watch) dans `deploy/rbac.yaml`.
- Rendu : visible dans **Explorer** (départ sur un Node → ses pods via `RUNS_ON`), catégorie de filtre **Nodes**, relation « tourne sur » dans le panneau, légende `infra`.
- Vérifié : test unitaire `collectNodes` (Node infra + IP, RUNS_ON correct, pod sans node ignoré) + rendu maquette Explorer.
**Reste optionnel** : une vue « placement » dédiée (pods groupés par node en bandes) — non requise, Explorer couvre le besoin. **Débloque ④.**

## ✅ ④ Onglet « chemins d'attaque » (privilege escalation croisée)
**Livré** : onglet **Chemins d'attaque** — flux gauche→droite d'escalade, composé côté frontend depuis `/graph` + `/findings` (aucune donnée neuve). Colonnes : entrée exposée → exécution → identité (SA) → capacité (RBAC / évasion) → actif critique. Cytoscape dédié (`acy`) : cartes + coudes + flux animé continu, arêtes colorées par gravité, techniques annotées.
- Primitives : exposition→workload, RUNS_AS (jeton SA), findings RBAC → capacité + actif (cluster-admin / secrets / node / impersonation), durcissement pod → évasion hôte, REFERENCES → secret.
- Entrée sélectionnable ; option « chemins vers actif critique » (intersection reachable-from-entrée ∩ reachable-to-jewel) ; entrée « compromission supposée » quand pas d'exposition.
- Garde-fous : chaque chemin étiqueté **POSSIBLE à vérifier** (PSA/OPA inconnu), posture défensive (« où couper »), aucun exploit.
- Vérifié : rendu maquette (2 entrées, 4 actifs critiques), aucune régression.
**V2 livré** :
- Évasion résolue vers le(s) **node(s) réel(s)** (via `RUNS_ON`) au lieu d'un « hôte » générique ; repli générique si RBAC `nodes` absente.
- **Pods voisins** co-hébergés sur le même node → arête « pod voisin (même hôte) » (mouvement latéral, borné à 4).
- **Scoring** des entrées : actifs critiques atteignables + pire gravité → tri du plus dangereux au moins, libellé dans le sélecteur (« … — critique · N actif(s) ») et statut « pire : … depuis … ».
- Vérifié : maquette avec placement (worker-1 réel + voisin prometheus) et scoring.

## (référence) ④ — conception initiale
**But** : à partir d'un point d'entrée, montrer en **flux** les étapes qu'un attaquant pourrait enchaîner jusqu'à un actif critique (crown jewel).
**Modèle** : graphe d'ATTEINTE = primitives d'escalade chaînées, construites sur la donnée déjà collectée.
Catalogue initial de primitives :
- Entrée exposée (LoadBalancer / NodePort / Ingress sans auth) → pod.
- Pod → SA (RUNS_AS) : héritage du token.
- SA → droits RBAC (GRANTS) : `*:*` (cluster-admin) · `get secrets` (creds) · `create pods` (→ pod privilégié → node) · `pods/exec` · `impersonate` · `escalate`/`bind`.
- Pod privilégié / hostPath / hostPID → **Node** (évasion) → pods voisins (RUNS_ON⁻¹) → leurs SA/secrets.
- Secret (REFERENCES) → creds → service cible.
- Flux autorisé (ALLOWS / TALKS_TO) → mouvement latéral.
**Décisions / garde-fous**
- Toujours « chemin **possible**, à vérifier » (admission control PSA/OPA inconnu) — jamais « certain ». Marquer un niveau de confiance.
- Point d'entrée **choisi** par l'utilisateur (nœud exposé, ou « ce pod est compromis ») ; ne montrer que ses chemins ; surligner ceux qui atteignent un crown jewel.
- Posture **défensive** : topologie des privilèges + « points de coupe recommandés ». Aucun payload, aucun exploit.
- Sous-étapes : **4a** moteur de primitives + calcul des chemins (BFS/DFS depuis l'entrée) ; **4b** rendu flux + sélecteur d'entrée + mise en avant crown jewels.
**Portée** : backend (moteur d'atteinte) + frontend (onglet flux). **RIO** : valeur maximale / coût élevé. **Dépendances** : ③a (évasion vers node).

## ✅ ③b Multi-cluster (affichage séparé)
**Livré** :
- Backend : `--contexts ctx1,ctx2` (ou `KUBEGRAPH_CONTEXTS`) → collecte séquentielle de N contextes kubeconfig, `ClusterID` = nom du contexte (`live.NewForContext`). Findings agrégés.
- Frontend : sélecteur **cluster** (affiché seulement si >1 cluster) scopant Exécution + départ Explorer ; la Vue d'ensemble sépare déjà par cluster (Cluster→NS→Types).
- `run.sh` propage `KUBEGRAPH_CONTEXTS`.
**Reste optionnel** : scoping cluster sur Réseau/Accès ; agent hub-spoke (archi cible).

## ✅ ② Terraform / Terragrunt (source déclarée infra-as-code)
**Livré** : `internal/source/declared/terraform.go` — `LoadTerraformJSON` lit `terraform show -json` (état) ou `planned_values` (plan), parcourt root + child modules, mappe `kubernetes_*` (variantes `_v1/_v2` normalisées) et `kubernetes_manifest` en Idents déclarables ; l'infra cloud (VPC, IAM, aws_*) est ignorée. Fusionné avec la source YAML dans `--tf-json` (ou `KUBEGRAPH_TFJSON`), même dérive de présence.
- Vérifié : test unitaire (Deployment/Service_v1/Ingress-manifest/ConfigMap lus, `aws_vpc` ignoré).
**Reste optionnel** : `helm_release` (chart entier, pas un objet unique) ; export cloud « infra » séparé.

## ❌ Ansible
Écarté : extraction d'objets K8s depuis des playbooks (Jinja2, boucles, templating) trop fragile pour une dérive fiable. À reconsidérer seulement via un callback `ansible-playbook --check` qui dumpe les objets rendus.

## 🧊 ⑤ Compatibilité EKS (AWS) — brainstorm
**But** : rendre le déploiement sur EKS propre et documenté (compatible aujourd'hui, mais avec des réserves à cadrer).
**Constat** : `client-go` + kubeconfig → tourne sur EKS en in-cluster read-only sans code spécifique. Points à traiter :
- **Auth IAM / RBAC** : mapper le ServiceAccount du hub aux droits lecture seule (aws-auth configMap **ou** EKS access entries — à confirmer selon version). Hors cluster : `aws eks get-token` (exec-plugin, géré par client-go) + droits IAM.
- **NetworkPolicy dépend du CNI** : VPC CNI par défaut n'applique les NetworkPolicies que si l'option est activée (ou Calico installé). Sinon policy déclarée ≠ appliquée → l'onglet Réseau peut montrer « isolé » à tort. → afficher un avertissement quand le CNI ne garantit pas l'enforcement.
- **Agent conntrack** : DaemonSet hostNetwork sur nœuds managés (dataplane iptables) = OK ; **Fargate** (pas d'accès hôte/DaemonSet) et dataplane **eBPF/Cilium** → trafic observé (`TALKS_TO`) indisponible, le reste du graphe fonctionne.
- **Cosmétique** : namespaces d'infra exclus nommés `calico-*` ; sur VPC CNI c'est `aws-node`/`kube-system` → adapter la liste `excludedNS`.
**À produire** : un guide de déploiement EKS (`deploy/eks.md`), un manifeste DaemonSet agent adapté, détection du CNI pour l'avertissement NetworkPolicy.
**Portée** : doc + manifestes + petit garde-fou UI. **RIO** : à évaluer selon la cible de déploiement. **Dépendances** : aucune (transversal).

---

## 🔜 D — Qualité des schémas (au Rafraîchir = régénération)
Principe : la donnée ne change qu'au snapshot/Rafraîchir → on peut investir une passe de layout soignée à ce moment, puis figer/cacher. Cadré aux 2 onglets les plus faibles + export.
- **Chemins d'attaque** : dé-collision des étiquettes d'arête (masquées par défaut, affichées au survol d'un nœud et quand une entrée précise est choisie) + espacement colonnes/lignes.
- **Explorer** : stabilité au dépliage — ne plus re-layouter tout le graphe à chaque expand ; positionner seulement les nouveaux nœuds près de leur voisin (positions existantes figées = effet « caché »).
- **Export** : bouton « exporter le schéma » par onglet → SVG (onglets Sankey, vectoriel net) / PNG (onglets Cytoscape via `cy.png`). Sert d'artefact partageable.

## ✅ FIX — faux « manquants » GitOps
Fait : `ConfigMap`/`RoleBinding`/`ClusterRoleBinding` retirés de `declarable` → plus de faux fantômes ambre sur la baseline.

## ✅ A — run.sh : assistant interactif (fait)
- Détection TTY (repli flags/env non-interactif), `.kubegraph.env` relu auto, `--setup` reconfigure.
- Questions : multi-cluster (`kubectl config get-contexts`) + source déclarée (snapshot / Terraform / Helm / GitHub avec `git clone` + token masqué). Vérif binaires, échecs propres. Syntaxe + repli testés.

## ✅ B — Nav 3 groupes (fait)
Groupes : Exploration (Explorer en tête) · Sécurité (Chemins d'attaque en 1er · Points d'attention · Flux de données) · Vue d'ensemble. Sous-onglets « type cahier » à droite. Vérifié via maquette.

## ✅ C — Onglet « Flux de données » (fait)
Trafic conntrack trié par risque : franchissement de frontière · porte un secret · non autorisé (observé sans NetworkPolicy). 3 toggles. Distinct de Réseau. Vérifié (3 badges déclenchés).

## ✅ ③b (suite) — scoping cluster Réseau & Accès (fait)
Sélecteur cluster étendu à Réseau & Accès (gate `clusterOk`), affiché si >1 cluster.

## ✅ ② (suite) — helm_release (fait)
`helm_release` déroulé via son `manifest` (si stocké) → parseur YAML partagé `identsFromRendered`.

## ✅ ④ (suite) — voisins co-hébergés portés à 8 (fait)

## ✅ 5 — Explorer : liseré sécurité (fait)
Chaque carte Explorer porteuse d'un point d'attention prend une bordure colorée par gravité (via `/findings` déjà chargé), seed inclus. Sécurité visible directement sur le graphe. Vérifié en maquette.

## 🔜 (ex-A, remplacé) — run.sh : assistant interactif (avec repli)
- **Détection TTY** : terminal → assistant ; pas de terminal (scheduled/CI) → comportement actuel par flags/env, inchangé.
- **Si `.kubegraph.env` existe** → le charger et lancer sans re-questionner (`./run.sh --setup` force la reconfiguration).
- **Questions posées** :
  1. **Multi-cluster** : lit `kubectl config get-contexts` ; si >1 → liste à cocher ; sinon contexte courant. → remplit `--contexts`. (1 cluster **primaire** porte la dérive déclarée.)
  2. **Source déclarée** (menu, mode GitOps) : `0` aucune · `1` snapshot cluster (kubectl) · `2` Terraform/Terragrunt (demande le dossier → `terraform show -json` → `KUBEGRAPH_TFJSON`) · `3` Helm (demande release+chart → `helm template` → `KUBEGRAPH_GITDIR`) · `4` GitHub (demande URL + token **masqué** → `git clone` → puis brut/helm/kustomize).
- **Garde-fous** : vérifier `kubectl/terraform/helm/git` présents, échouer proprement ; token via `read -s`, **jamais** en argument ni dans l'historique ; réponses sauvées dans `.kubegraph.env`.

## 🔜 B — Réorganisation nav : 3 groupes, 2 niveaux
- Rangée 1 (groupes) : **Vue d'ensemble** · **Exploration** · **Sécurité**.
- Rangée 2 (sous-onglets « type cahier », à droite), selon le groupe actif :
  - Exploration → Explorer · Réseau & interactions · Exécution · Accès & identité (les onglets « loupe » mis en avant).
  - Sécurité → **Chemins d'attaque** (1er) · Points d'attention · **Flux de données**.
  - Vue d'ensemble → pas de sous-onglet.
- Frontend seul : mapping `data-mode` → groupe, CSS de la 2ᵉ rangée, routage. Sobre, pas décoratif.

## 🔜 C — Nouvel onglet « Flux de données » (sous Sécurité)
Une vue flux (réutilise le rendu Sankey/tube) avec 3 angles combinables (toggles), sur le graphe + findings réseau existants :
- **Franchissement de frontière** : arêtes changeant de namespace / vers exposition (LB/Ingress) / externe / autre cluster.
- **Flux portant un secret** : workload qui `REFERENCES` un secret puis parle à d'autres (propagation de credentials).
- **Observé vs autorisé** : flux conntrack (`TALKS_TO`) non couverts par une NetworkPolicy (recoupe le finding « dérive réseau », en vue flux).
Angle propre = « où circule / franchit / échappe la donnée sensible », distinct de « qui parle à qui » (Réseau).

---

## Ordre d'exécution retenu
FIX → A (wizard) → B (nav) → C (flux de données) · puis ⑤ EKS · reste optionnel
Historique : ① → ③a → ④ (4a, 4b, V2) → ③b → ② (faits)
