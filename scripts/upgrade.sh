#!/usr/bin/env bash
# =============================================================================
# upgrade.sh — Rolling upgrade of TalosOS on cluster nodes
#
# Usage:
#   ./scripts/upgrade.sh [HOSTNAME ...]
#
# If no hostnames are given, upgrades ALL nodes in safe order:
#   workers first → non-bootstrap CP → bootstrap CP last
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${ROOT_DIR}/cluster/config.env"

S3_DIR="${ROOT_DIR}/${LOCAL_S3_DIR}"
TALOSCONFIG="${S3_DIR}/configs/talosconfig"
BOOTSTRAP_HOSTNAME="${BOOTSTRAP_NODE%%:*}"

# ---------------------------------------------------------------------------
# Build node lookup
# ---------------------------------------------------------------------------
declare -A NODE_IP=()
VALID_HOSTNAMES=()
for entry in ${CP_NODES} ${WORKER_NODES}; do
    h="${entry%%:*}"; ip="${entry##*:}"
    NODE_IP["${h}"]="${ip}"
    VALID_HOSTNAMES+=("${h}")
done

# ---------------------------------------------------------------------------
# Determine upgrade order
# ---------------------------------------------------------------------------
TARGETS=("$@")

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    # Safe order: workers → non-bootstrap CP → bootstrap CP
    TARGETS=()
    for entry in ${WORKER_NODES}; do
        TARGETS+=("${entry%%:*}")
    done
    for entry in ${CP_NODES}; do
        h="${entry%%:*}"
        [[ "${h}" == "${BOOTSTRAP_HOSTNAME}" ]] && continue
        TARGETS+=("${h}")
    done
    TARGETS+=("${BOOTSTRAP_HOSTNAME}")
fi

# ---------------------------------------------------------------------------
# Preflight validation
# ---------------------------------------------------------------------------
UNKNOWN_TARGETS=()
for hostname in "${TARGETS[@]}"; do
    if [[ ! -v "NODE_IP[$hostname]" ]]; then
        UNKNOWN_TARGETS+=("${hostname}")
    fi
done

if [[ ${#UNKNOWN_TARGETS[@]} -gt 0 ]]; then
    echo "ERROR: Unknown node target(s): ${UNKNOWN_TARGETS[*]}" >&2
    echo "Valid nodes: ${VALID_HOSTNAMES[*]}" >&2
    exit 1
fi

if [[ ! -f "${TALOSCONFIG}" ]]; then
    echo "ERROR: Talosconfig not found at ${TALOSCONFIG}" >&2
    echo "Run 'make s3-pull' or 'make generate' before upgrading." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
echo "============================================================"
echo "  TALOS ROLLING UPGRADE"
echo "============================================================"
echo ""
echo "  Target version: ${TALOS_VERSION}"
echo "  Install image:  ${TALOS_INSTALL_IMAGE}"
echo "  Upgrade order:  ${TARGETS[*]}"
echo ""
read -p "  Type 'yes' to proceed: " confirm
if [[ "${confirm}" != "yes" ]]; then
    echo "  Aborted."
    exit 1
fi

# ---------------------------------------------------------------------------
# Rolling upgrade
# ---------------------------------------------------------------------------
for hostname in "${TARGETS[@]}"; do
    ip="${NODE_IP[${hostname}]}"
    echo ""
    echo "==> Upgrading ${hostname} (${ip})..."

    talosctl upgrade \
        --talosconfig "${TALOSCONFIG}" \
        --nodes "${ip}" \
        --image "${TALOS_INSTALL_IMAGE}" \
        --preserve

    echo "==> Waiting for ${hostname} to rejoin and become healthy..."
    talosctl health \
        --talosconfig "${TALOSCONFIG}" \
        --nodes "${ip}" \
        --wait-timeout 10m

    echo "==> ${hostname} upgraded successfully."
done

echo ""
echo "============================================================"
echo "  ALL NODES UPGRADED TO ${TALOS_VERSION}"
echo "============================================================"
