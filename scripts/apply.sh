#!/usr/bin/env bash
# =============================================================================
# apply.sh — Apply machine configs to Talos nodes
#
# Usage:
#   ./scripts/apply.sh [--insecure] [HOSTNAME ...]
#
# If no hostnames are given, applies to ALL nodes in conservative order:
# workers first, then non-bootstrap control planes, then bootstrap last.
# Use --insecure for initial provisioning before PKI is established.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${ROOT_DIR}/cluster/config.env"

S3_DIR="${ROOT_DIR}/${LOCAL_S3_DIR}"
TALOSCONFIG="${S3_DIR}/configs/talosconfig"
BOOTSTRAP_HOSTNAME="${BOOTSTRAP_NODE%%:*}"
INSECURE=""
TARGETS=()

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --insecure) INSECURE="--insecure"; shift ;;
        *)          TARGETS+=("$1");        shift ;;
    esac
done

# ---------------------------------------------------------------------------
# Build node lookup
# ---------------------------------------------------------------------------
declare -A NODE_IP=()
declare -A NODE_ROLE=()

for entry in ${CP_NODES}; do
    h="${entry%%:*}"; ip="${entry##*:}"
    NODE_IP["${h}"]="${ip}"
    NODE_ROLE["${h}"]="controlplane"
done
for entry in ${WORKER_NODES}; do
    h="${entry%%:*}"; ip="${entry##*:}"
    NODE_IP["${h}"]="${ip}"
    NODE_ROLE["${h}"]="worker"
done

# Default: all nodes in a deterministic, control-plane-safe order.
if [[ ${#TARGETS[@]} -eq 0 ]]; then
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
# Preflight: validate every target before any talosctl invocation so a
# typo or missing generated config rejects the whole run instead of leaving
# the cluster in a partial-apply state.
# ---------------------------------------------------------------------------
UNKNOWN=()
MISSING=()
for hostname in "${TARGETS[@]}"; do
    if [[ -z "${NODE_IP[${hostname}]+x}" ]]; then
        UNKNOWN+=("${hostname}")
        continue
    fi
    role="${NODE_ROLE[${hostname}]}"
    config_path="${S3_DIR}/generated/${role}/${hostname}.yaml"
    if [[ ! -f "${config_path}" ]]; then
        MISSING+=("${config_path}")
    fi
done

if (( ${#UNKNOWN[@]} > 0 )); then
    for h in "${UNKNOWN[@]}"; do
        echo "ERROR: Unknown node '${h}'"
    done
    echo "Valid nodes: ${!NODE_IP[*]}"
fi
if (( ${#MISSING[@]} > 0 )); then
    for p in "${MISSING[@]}"; do
        echo "ERROR: Config not found at ${p}"
    done
    echo "Run 'make generate' first."
fi
if (( ${#UNKNOWN[@]} > 0 || ${#MISSING[@]} > 0 )); then
    exit 1
fi

# ---------------------------------------------------------------------------
# Apply configs
# ---------------------------------------------------------------------------
for hostname in "${TARGETS[@]}"; do
    ip="${NODE_IP[${hostname}]}"
    role="${NODE_ROLE[${hostname}]}"
    config_path="${S3_DIR}/generated/${role}/${hostname}.yaml"

    echo "==> Applying config to ${hostname} (${ip}) [${role}]..."
    talosctl apply-config \
        --talosconfig "${TALOSCONFIG}" \
        --nodes "${ip}" \
        --file "${config_path}" \
        ${INSECURE}
    echo "    Done."
done

echo ""
echo "==> All configs applied successfully!"
