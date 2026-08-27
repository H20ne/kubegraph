#!/usr/bin/env bash
# Lance kubegraph en UNE commande : hub + agent conntrack embarqué, un seul process.
#
#   ./run.sh                              # collecte le cluster, sert l'API :8080, capte le trafic
#   KUBEGRAPH_ADDR=:9090 ./run.sh
#
#   # --- Mode GitOps (dérive déclaré vs observé) ---
#   ./run.sh --git-snapshot [DOSSIER]     # génère une baseline de YAML depuis le cluster (défaut: ./gitops-snapshot)
#   KUBEGRAPH_GITDIR=./gitops-snapshot ./run.sh   # active le mode GitOps sur ce dossier
#   ./run.sh --git-dir ./mes-manifests-rendus     # idem, en flag
#
# L'agent embarqué lit /proc/net/nf_conntrack (root requis) → on relance sous sudo
# en préservant l'environnement (KUBECONFIG, PATH, GOPATH…). Ctrl-C arrête tout.
set -euo pipefail
cd "$(dirname "$0")"

# Environnement Go non persistant (cas GPE-NYX : Go dans /tmp/kg).
if [ -f /tmp/kg/env.sh ]; then source /tmp/kg/env.sh; fi
GO="$(command -v go || echo /tmp/kg/goroot/bin/go)"
[ -x "$GO" ] || { echo "Go introuvable (ni dans le PATH, ni /tmp/kg/goroot/bin/go)"; exit 1; }

export KUBEGRAPH_ADDR="${KUBEGRAPH_ADDR:-:8080}"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# ---------------------------------------------------------------------------
# --git-snapshot : écrit l'état DÉCLARABLE du cluster dans un dossier de YAML.
# C'est une BASELINE : tout sortira « en phase » (vert) au premier lancement —
# la preuve que le pipeline marche. Ensuite tu remplaces ce dossier par la sortie
# de `helm template` / `kustomize build` de ton Git pour voir la vraie dérive.
# On ne dumpe QUE les kinds déclarables (jamais Pod/ReplicaSet/Secret : générés/sensibles).
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--git-snapshot" ]; then
  DIR="${2:-gitops-snapshot}"
  command -v kubectl >/dev/null || { echo "kubectl requis pour --git-snapshot"; exit 1; }
  mkdir -p "$DIR"
  OUT="$DIR/rendered.yaml"; : > "$OUT"
  NS_KINDS="deployments statefulsets daemonsets jobs cronjobs services ingresses configmaps networkpolicies serviceaccounts roles rolebindings horizontalpodautoscalers poddisruptionbudgets persistentvolumeclaims"
  CL_KINDS="clusterroles clusterrolebindings"
  TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
  echo "→ snapshot des ressources déclarables du cluster vers $OUT"
  for k in $NS_KINDS; do
    # -o yaml renvoie un « List » ; le lecteur kubegraph sait le dérouler.
    if kubectl get "$k" -A -o yaml --show-managed-fields=false >"$TMP" 2>/dev/null; then
      cat "$TMP" >> "$OUT"; echo "---" >> "$OUT"
    fi
  done
  for k in $CL_KINDS; do
    if kubectl get "$k" -o yaml --show-managed-fields=false >"$TMP" 2>/dev/null; then
      cat "$TMP" >> "$OUT"; echo "---" >> "$OUT"
    fi
  done
  echo "✓ baseline écrite : $OUT"
  echo "→ lance ensuite :  KUBEGRAPH_GITDIR=$DIR ./run.sh"
  echo "  puis coche « mode GitOps » dans le dashboard (tout en phase = vert)."
  exit 0
fi

# Sources déclarées / multi-cluster : flags ou variables d'environnement.
#   KUBEGRAPH_GITDIR   dossier de YAML rendus (dérive GitOps)
#   KUBEGRAPH_TFJSON   fichier `terraform show -json` (dérive Terraform, K8s only)
#   KUBEGRAPH_CONTEXTS contextes kubeconfig séparés par des virgules (multi-cluster)
EXTRA_ARGS=()
if [ "${1:-}" = "--git-dir" ] && [ -n "${2:-}" ]; then
  EXTRA_ARGS+=(--git-dir "$2"); export KUBEGRAPH_GITDIR="$2"
elif [ -n "${KUBEGRAPH_GITDIR:-}" ]; then
  EXTRA_ARGS+=(--git-dir "$KUBEGRAPH_GITDIR")
fi
[ -n "${KUBEGRAPH_TFJSON:-}" ]   && EXTRA_ARGS+=(--tf-json "$KUBEGRAPH_TFJSON")
[ -n "${KUBEGRAPH_CONTEXTS:-}" ] && EXTRA_ARGS+=(--contexts "$KUBEGRAPH_CONTEXTS")

# Déjà root ? on lance directement. Sinon on repasse sous sudo en gardant l'env.
if [ "$(id -u)" -eq 0 ]; then
  exec "$GO" run ./cmd/kubegraph --agent "${EXTRA_ARGS[@]}"
else
  echo "→ élévation sudo (lecture conntrack) ; l'environnement est préservé."
  exec sudo -E env "PATH=$PATH" "KUBECONFIG=$KUBECONFIG" "KUBEGRAPH_ADDR=$KUBEGRAPH_ADDR" \
    "KUBEGRAPH_GITDIR=${KUBEGRAPH_GITDIR:-}" "KUBEGRAPH_TFJSON=${KUBEGRAPH_TFJSON:-}" "KUBEGRAPH_CONTEXTS=${KUBEGRAPH_CONTEXTS:-}" \
    "$GO" run ./cmd/kubegraph --agent "${EXTRA_ARGS[@]}"
fi
