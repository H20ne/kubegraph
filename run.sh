#!/usr/bin/env bash
# Lance kubegraph en UNE commande : hub + agent conntrack embarqué, un seul process.
#
#   ./run.sh                 # collecte le cluster, sert l'API :8080, capte le trafic
#   KUBEGRAPH_ADDR=:9090 ./run.sh
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

# Déjà root ? on lance directement. Sinon on repasse sous sudo en gardant l'env.
if [ "$(id -u)" -eq 0 ]; then
  exec "$GO" run ./cmd/kubegraph --agent
else
  echo "→ élévation sudo (lecture conntrack) ; l'environnement est préservé."
  exec sudo -E env "PATH=$PATH" "KUBECONFIG=$KUBECONFIG" "KUBEGRAPH_ADDR=$KUBEGRAPH_ADDR" \
    "$GO" run ./cmd/kubegraph --agent
fi
