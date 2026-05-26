#!/usr/bin/env bash
# =============================================================================
# drift-check.sh — verify the repo's declarative state matches the live cluster.
#
# Steps:
#   1. Back up the operator-issued .s3/configs/talosconfig (scripts/generate.sh
#      regenerates it and would lose endpoints/nodes).
#   2. Regenerate machine configs locally from cluster/patches + secrets.
#   3. Restore the talosconfig.
#   4. For each node in cluster/config.env, pull the live machineconfig.
#   5. Capture the live kube-apiserver server gitVersion.
#   6. Invoke scripts/diff-vs-live.py to compare structurally.
#
# Exits 0 on no drift, 1 on drift, 2 on input/runtime errors. Implements
# the ADR-0003 §Confirmation §3 drift-detection requirement.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

source cluster/config.env

S3_DIR="${LOCAL_S3_DIR}"
TALOSCONFIG="${S3_DIR}/configs/talosconfig"
KUBECONFIG_PATH="${S3_DIR}/configs/kubeconfig"

if [[ ! -f "${TALOSCONFIG}" ]]; then
    echo "ERROR: talosconfig not found at ${TALOSCONFIG}" >&2
    echo "       Run 'make s3-pull' first." >&2
    exit 2
fi
if [[ ! -f "${KUBECONFIG_PATH}" ]]; then
    echo "ERROR: kubeconfig not found at ${KUBECONFIG_PATH}" >&2
    exit 2
fi

LIVE_DIR=$(mktemp -d)
BACKUP_TALOSCONFIG=$(mktemp)
cleanup() {
    rm -rf "${LIVE_DIR}"
    rm -f "${BACKUP_TALOSCONFIG}"
}
trap cleanup EXIT

echo "==> Drift check started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Preserve operator-issued talosconfig: scripts/generate.sh overwrites it
# with a freshly-issued one that has empty endpoints/nodes, breaking
# subsequent talosctl calls in this script.
cp "${TALOSCONFIG}" "${BACKUP_TALOSCONFIG}"

echo "==> Regenerating local machine configs"
bash scripts/generate.sh > /dev/null

# Restore the operator's talosconfig (with endpoints + nodes populated)
cp "${BACKUP_TALOSCONFIG}" "${TALOSCONFIG}"

echo "==> Pulling live machineconfig from each node"
for entry in ${CP_NODES} ${WORKER_NODES}; do
    name="${entry%%:*}"
    ip="${entry##*:}"
    out_file="${LIVE_DIR}/${ip}.machineconfig-resource.yaml"
    if ! talosctl --talosconfig "${TALOSCONFIG}" --nodes "${ip}" \
            get machineconfig -o yaml > "${out_file}" 2>/dev/null; then
        echo "ERROR: failed to pull machineconfig from ${name} (${ip})" >&2
        exit 2
    fi
done

echo "==> Reading kube-apiserver server gitVersion"
SERVER_VER=$(
    kubectl --kubeconfig "${KUBECONFIG_PATH}" version --output=json 2>/dev/null \
    | python -c "import sys,json; print(json.load(sys.stdin)['serverVersion']['gitVersion'])"
)
if [[ -z "${SERVER_VER}" ]]; then
    echo "ERROR: could not read kube-apiserver server version" >&2
    exit 2
fi

echo "==> Running structural diff"
echo
python scripts/diff-vs-live.py "${LIVE_DIR}" --kube-version "${SERVER_VER}"
