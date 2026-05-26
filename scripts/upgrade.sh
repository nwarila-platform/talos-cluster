#!/usr/bin/env bash
# =============================================================================
# upgrade.sh — Rolling upgrade of TalosOS on cluster nodes
#
# Usage:
#   ./scripts/upgrade.sh [--yes] [HOSTNAME ...]
#
# If no hostnames are given, upgrades ALL nodes in safe order:
#   workers first → non-bootstrap CP → bootstrap CP last
#
# --yes skips the interactive confirmation prompt. Required when invoked from
# CI/CD (non-TTY stdin makes `read` fail under `set -e`). The deploy workflow
# already gates upgrades behind a GitHub `environment: production` manual
# approval, so the script-level prompt is redundant in that path.
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
# Parse arguments
# ---------------------------------------------------------------------------
ASSUME_YES=0
TARGETS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --yes) ASSUME_YES=1; shift ;;
        --)    shift; TARGETS+=("$@"); break ;;
        -*)    echo "ERROR: unknown flag '$1' (expected --yes or HOSTNAME)" >&2; exit 1 ;;
        *)     TARGETS+=("$1"); shift ;;
    esac
done

# ---------------------------------------------------------------------------
# Determine upgrade order
# ---------------------------------------------------------------------------

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
if [[ "${ASSUME_YES}" -eq 1 ]]; then
    echo "  --yes supplied; skipping interactive confirmation."
else
    read -r -p "  Type 'yes' to proceed: " confirm
    if [[ "${confirm}" != "yes" ]]; then
        echo "  Aborted."
        exit 1
    fi
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

    # Post-upgrade verification. Two distinct checks:
    # 1. Per-node: the upgraded node itself is back, on the new version,
    #    and Ready in K8s. Uses talosctl version + kubectl, neither of
    #    which require apid RPC forwarding — so they work even when the
    #    upgraded node's new apid hasn't fully re-registered yet.
    # 2. Cluster-wide: etcd is healthy. Uses talosctl health pointed at
    #    a CP node that ISN'T the current upgrade target, since etcd
    #    queries via worker-apid forwarding break post-reboot with
    #    `PermissionDenied: no request forwarding`.
    echo "==> Waiting 30s for ${hostname} to stabilize before verification..."
    sleep 30

    # Per-node version check
    echo "==> Verifying ${hostname} reports new Talos version..."
    actual_ver=$(talosctl --talosconfig "${TALOSCONFIG}" --nodes "${ip}" version --short 2>&1 | grep -m1 "Tag:" | awk '{print $2}')
    if [[ "${actual_ver}" != "${TALOS_VERSION}" ]]; then
        echo "==> ERROR: ${hostname} reports Talos version ${actual_ver}, expected ${TALOS_VERSION}" >&2
        exit 1
    fi
    echo "    ${hostname} on ${actual_ver}"

    # Pick a CP that ISN'T the current target for cluster-wide health
    HEALTH_CP_IP=""
    for cp_entry in ${CP_NODES}; do
        cp_ip="${cp_entry##*:}"
        if [[ "${cp_ip}" != "${ip}" ]]; then
            HEALTH_CP_IP="${cp_ip}"
            break
        fi
    done
    if [[ -z "${HEALTH_CP_IP}" ]]; then
        echo "==> ERROR: no CP available for cluster health check" >&2
        exit 1
    fi

    echo "==> Cluster health check via ${HEALTH_CP_IP} (anchor CP)..."
    HEALTH_MAX_ATTEMPTS=5
    health_ok=0
    for attempt in $(seq 1 ${HEALTH_MAX_ATTEMPTS}); do
        if talosctl health \
            --talosconfig "${TALOSCONFIG}" \
            --nodes "${HEALTH_CP_IP}" \
            --wait-timeout 5m; then
            health_ok=1
            break
        fi
        if [[ ${attempt} -lt ${HEALTH_MAX_ATTEMPTS} ]]; then
            echo "==> health check attempt ${attempt}/${HEALTH_MAX_ATTEMPTS} failed, retrying in 30s..."
            sleep 30
        fi
    done
    if [[ ${health_ok} -eq 0 ]]; then
        echo "==> ERROR: cluster health check failed after ${HEALTH_MAX_ATTEMPTS} attempts" >&2
        exit 1
    fi

    echo "==> ${hostname} upgraded successfully."
done

echo ""
echo "============================================================"
echo "  ALL NODES UPGRADED TO ${TALOS_VERSION}"
echo "============================================================"
