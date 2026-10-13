#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"
STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
TALOSCONFIG="${STATE_ROOT}/configs/talosconfig"
KUBECONFIG="${KUBECONFIG:-${STATE_ROOT}/configs/kubeconfig}"
export KUBECONFIG

CP_IPS=""
WORKER_IPS=""
for entry in ${CP_NODES}; do CP_IPS="${CP_IPS:+${CP_IPS},}${entry##*:}"; done
for entry in ${WORKER_NODES}; do WORKER_IPS="${WORKER_IPS:+${WORKER_IPS},}${entry##*:}"; done

talosctl health --talosconfig "${TALOSCONFIG}" --nodes "${BOOTSTRAP_NODE##*:}" \
    --control-plane-nodes "${CP_IPS}" --worker-nodes "${WORKER_IPS}" --wait-timeout 5m
kubectl get nodes -o wide
kubectl get pods -A
helm list -A
