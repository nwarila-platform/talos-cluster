#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

if [[ "${CONFIRM_REBUILD:-}" != "TDNHQ-TALCL01" ]]; then
    echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to authorize one-time bootstrap" >&2
    exit 1
fi

STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
TALOSCONFIG="${STATE_ROOT}/configs/talosconfig"
BOOTSTRAP_IP="${BOOTSTRAP_NODE##*:}"
[[ -f "${TALOSCONFIG}" ]] || { echo "ERROR: run make generate first" >&2; exit 1; }

talosctl bootstrap --talosconfig "${TALOSCONFIG}" \
    --endpoints "${BOOTSTRAP_IP}" --nodes "${BOOTSTRAP_IP}"
talosctl kubeconfig --talosconfig "${TALOSCONFIG}" \
    --endpoints "${BOOTSTRAP_IP}" --nodes "${BOOTSTRAP_IP}" \
    --force "${STATE_ROOT}/configs/kubeconfig"

echo "Bootstrap complete. Install networking immediately with: make platform"
