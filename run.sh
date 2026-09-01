#!/usr/bin/env bash
# Lance kubegraph : hub + agent conntrack embarqué, un seul process.
#
#   ./run.sh                 # 1er lancement interactif : assistant de configuration
#   ./run.sh --setup         # relance l'assistant (reconfigurer)
#   ./run.sh --git-snapshot [DOSSIER]   # baseline YAML depuis le cluster (sans assistant)
#
# L'assistant (si terminal) demande : quels clusters collecter, et la source
# déclarée pour le mode GitOps (snapshot / Terraform / Helm / GitHub). Les réponses
# sont sauvées dans .kubegraph.env et relues automatiquement ensuite (jamais de token).
# Sans terminal (scheduled/CI) et sans .kubegraph.env : comportement par flags/env.
#
# L'agent embarqué lit /proc/net/nf_conntrack (root requis) → relance sous sudo en
# préservant l'environnement. Ctrl-C arrête tout.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f /tmp/kg/env.sh ]; then source /tmp/kg/env.sh; fi   # Go non persistant (GPE-NYX)
GO="$(command -v go || echo /tmp/kg/goroot/bin/go)"
[ -x "$GO" ] || { echo "Go introuvable (ni dans le PATH, ni /tmp/kg/goroot/bin/go)"; exit 1; }

export KUBEGRAPH_ADDR="${KUBEGRAPH_ADDR:-:8080}"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
ENVFILE=".kubegraph.env"

# --- snapshot : dump des kinds DÉCLARABLES du cluster (jamais Pod/Secret/ConfigMap) ---
do_snapshot() {
  local DIR="${1:-gitops-snapshot}"
  command -v kubectl >/dev/null || { echo "kubectl requis pour le snapshot"; return 1; }
  mkdir -p "$DIR"; local OUT="$DIR/rendered.yaml"; : > "$OUT"
  local NS_KINDS="deployments statefulsets daemonsets jobs cronjobs services ingresses networkpolicies serviceaccounts roles horizontalpodautoscalers poddisruptionbudgets persistentvolumeclaims"
  local CL_KINDS="clusterroles"
  local TMP; TMP="$(mktemp)"
  echo "→ snapshot des ressources déclarables vers $OUT"
  for k in $NS_KINDS; do kubectl get "$k" -A -o yaml --show-managed-fields=false >"$TMP" 2>/dev/null && { cat "$TMP" >>"$OUT"; echo "---" >>"$OUT"; }; done
  for k in $CL_KINDS; do kubectl get "$k"    -o yaml --show-managed-fields=false >"$TMP" 2>/dev/null && { cat "$TMP" >>"$OUT"; echo "---" >>"$OUT"; }; done
  rm -f "$TMP"; echo "✓ $OUT"
}

# --git-snapshot : snapshot seul, sans assistant, sans lancer le hub.
if [ "${1:-}" = "--git-snapshot" ]; then
  do_snapshot "${2:-gitops-snapshot}"
  echo "→ lance ensuite :  KUBEGRAPH_GITDIR=${2:-./gitops-snapshot} ./run.sh"
  exit 0
fi

# --- Assistant interactif : remplit KUBEGRAPH_CONTEXTS / GITDIR / TFJSON ---
run_wizard() {
  echo "═══ Assistant kubegraph ═══  (Entrée = valeur par défaut)"
  # 1) Multi-cluster.
  local CTX=(); command -v kubectl >/dev/null && mapfile -t CTX < <(kubectl config get-contexts -o name 2>/dev/null) || true
  if [ "${#CTX[@]}" -gt 1 ]; then
    echo "Contextes kubeconfig détectés :"; local i=1; for c in "${CTX[@]}"; do echo "  $i) $c"; i=$((i+1)); done
    read -r -p "Clusters à collecter (numéros séparés par des virgules · 'a'=tous · Entrée=courant) : " ans
    if [ "${ans:-}" = "a" ]; then WIZ_CONTEXTS="$(IFS=,; echo "${CTX[*]}")"
    elif [ -n "${ans:-}" ]; then local sel="" num; IFS=',' read -ra nums <<< "$ans"
      for num in "${nums[@]}"; do num="${num// /}"; [ -n "$num" ] && sel="${sel:+$sel,}${CTX[$((num-1))]}"; done; WIZ_CONTEXTS="$sel"
    fi
    [ -n "${WIZ_CONTEXTS:-}" ] && echo "  → clusters : $WIZ_CONTEXTS"
  fi
  # 2) Source déclarée (mode GitOps).
  echo "Source déclarée (mode GitOps) :"
  echo "  0) aucune   1) snapshot du cluster   2) Terraform/Terragrunt   3) Helm   4) GitHub"
  read -r -p "Choix [0] : " src; src="${src:-0}"
  case "$src" in
    1) do_snapshot gitops-snapshot && WIZ_GITDIR="./gitops-snapshot" ;;
    2) if command -v terraform >/dev/null; then
         read -r -p "Dossier Terraform (où lancer 'terraform show') : " td
         terraform -chdir="$td" show -json > .kubegraph-tf.json 2>/dev/null && WIZ_TFJSON="./.kubegraph-tf.json" || echo "  terraform show a échoué (état accessible ?)"
       else echo "  terraform absent — ignoré"; fi ;;
    3) if command -v helm >/dev/null; then
         echo "  releases déployées :"; helm list -A 2>/dev/null | awk 'NR>1{printf "    - %s (ns %s)\n",$1,$2}'
         read -r -p "Nom de release : " rel; read -r -p "Namespace de la release : " rns
         # helm get manifest = YAML rendu de la release DÉPLOYÉE (pas besoin du chart local).
         mkdir -p gitops
         if helm get manifest "$rel" -n "$rns" > gitops/rendered.yaml 2>/dev/null && [ -s gitops/rendered.yaml ]; then
           WIZ_GITDIR="./gitops"
         else echo "  'helm get manifest $rel -n $rns' a échoué ou vide (release/namespace ? release 'failed' ?)"; fi
       else echo "  helm absent — ignoré"; fi ;;
    4) if command -v git >/dev/null; then
         read -r -p "URL du repo GitHub : " url
         read -r -p "Repo privé ? [o/N] : " priv
         if [ "${priv:-}" = "o" ] || [ "${priv:-}" = "O" ]; then read -r -s -p "Token (NON sauvegardé) : " tok; echo; url="https://${tok}@${url#https://}"; fi
         rm -rf gitops-repo; if git clone --depth 1 "$url" gitops-repo 2>/dev/null; then
           read -r -p "Format du repo :  1) YAML brut   2) Helm   3) Kustomize  [1] : " fmt; fmt="${fmt:-1}"
           case "$fmt" in
             2) read -r -p "Release : " rel; read -r -p "Chart (chemin dans gitops-repo/) : " ch
                mkdir -p gitops; helm template "$rel" "gitops-repo/$ch" > gitops/rendered.yaml 2>/dev/null && WIZ_GITDIR="./gitops" || echo "  helm template a échoué" ;;
             3) read -r -p "Overlay (chemin dans gitops-repo/) : " ov
                mkdir -p gitops; kustomize build "gitops-repo/$ov" > gitops/rendered.yaml 2>/dev/null && WIZ_GITDIR="./gitops" || echo "  kustomize build a échoué" ;;
             *) WIZ_GITDIR="./gitops-repo" ;;
           esac
         else echo "  clone échoué (URL / droits ?)"; fi
       else echo "  git absent — ignoré"; fi ;;
    *) : ;;
  esac
  # Sauvegarde (sans token) + export pour ce lancement.
  { echo "# généré par ./run.sh --setup — éditable, relu automatiquement"
    [ -n "${WIZ_CONTEXTS:-}" ] && echo "KUBEGRAPH_CONTEXTS=$WIZ_CONTEXTS"
    [ -n "${WIZ_GITDIR:-}"   ] && echo "KUBEGRAPH_GITDIR=$WIZ_GITDIR"
    [ -n "${WIZ_TFJSON:-}"   ] && echo "KUBEGRAPH_TFJSON=$WIZ_TFJSON"
  } > "$ENVFILE"
  echo "→ réponses sauvées dans $ENVFILE  (./run.sh --setup pour reconfigurer)"
  [ -n "${WIZ_CONTEXTS:-}" ] && export KUBEGRAPH_CONTEXTS="$WIZ_CONTEXTS"
  [ -n "${WIZ_GITDIR:-}"   ] && export KUBEGRAPH_GITDIR="$WIZ_GITDIR"
  [ -n "${WIZ_TFJSON:-}"   ] && export KUBEGRAPH_TFJSON="$WIZ_TFJSON"
}

# Décision : --setup force l'assistant ; sinon .kubegraph.env s'il existe ; sinon
# assistant si terminal ; sinon flags/env seuls (non-interactif).
if [ "${1:-}" = "--setup" ]; then run_wizard
elif [ -f "$ENVFILE" ]; then set -a; source "$ENVFILE"; set +a
elif [ -t 0 ]; then run_wizard
fi

# --git-dir passé en flag prime sur l'env.
if [ "${1:-}" = "--git-dir" ] && [ -n "${2:-}" ]; then export KUBEGRAPH_GITDIR="$2"; fi

EXTRA_ARGS=()
[ -n "${KUBEGRAPH_GITDIR:-}"   ] && EXTRA_ARGS+=(--git-dir  "$KUBEGRAPH_GITDIR")
[ -n "${KUBEGRAPH_TFJSON:-}"   ] && EXTRA_ARGS+=(--tf-json  "$KUBEGRAPH_TFJSON")
[ -n "${KUBEGRAPH_CONTEXTS:-}" ] && EXTRA_ARGS+=(--contexts "$KUBEGRAPH_CONTEXTS")

if [ "$(id -u)" -eq 0 ]; then
  exec "$GO" run ./cmd/kubegraph --agent "${EXTRA_ARGS[@]}"
else
  echo "→ élévation sudo (lecture conntrack) ; l'environnement est préservé."
  exec sudo -E env "PATH=$PATH" "KUBECONFIG=$KUBECONFIG" "KUBEGRAPH_ADDR=$KUBEGRAPH_ADDR" \
    "KUBEGRAPH_GITDIR=${KUBEGRAPH_GITDIR:-}" "KUBEGRAPH_TFJSON=${KUBEGRAPH_TFJSON:-}" "KUBEGRAPH_CONTEXTS=${KUBEGRAPH_CONTEXTS:-}" \
    "$GO" run ./cmd/kubegraph --agent "${EXTRA_ARGS[@]}"
fi
