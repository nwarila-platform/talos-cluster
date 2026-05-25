#!/usr/bin/env bash
# =============================================================================
# health.sh — Cluster health checks
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${ROOT_DIR}/cluster/config.env"

S3_DIR="${ROOT_DIR}/${LOCAL_S3_DIR}"
TALOSCONFIG="${S3_DIR}/configs/talosconfig"

# Build node IP lists
CP_IPS=""
WORKER_IPS=""
ALL_IPS=""
for entry in ${CP_NODES}; do
    ip="${entry##*:}"
    CP_IPS="${CP_IPS:+${CP_IPS},}${ip}"
    ALL_IPS="${ALL_IPS:+${ALL_IPS},}${ip}"
done
for entry in ${WORKER_NODES}; do
    ip="${entry##*:}"
    WORKER_IPS="${WORKER_IPS:+${WORKER_IPS},}${ip}"
    ALL_IPS="${ALL_IPS:+${ALL_IPS},}${ip}"
done

echo "============================================================"
echo "  CLUSTER HEALTH CHECK — ${CLUSTER_NAME}"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# Talos health
# ---------------------------------------------------------------------------
echo "--- Talos Service Health ---"
# Talos 1.12+ health command requires single --nodes, uses --control-plane-nodes
FIRST_CP=$(echo "${CP_IPS}" | cut -d',' -f1)
HEALTH_FAILED=0
if ! talosctl health \
    --talosconfig "${TALOSCONFIG}" \
    --nodes "${FIRST_CP}" \
    --control-plane-nodes "${CP_IPS}" \
    --worker-nodes "${WORKER_IPS}" \
    --wait-timeout 5m; then
    echo "ERROR: Talos health check reported issues." >&2
    HEALTH_FAILED=1
fi
echo ""

# ---------------------------------------------------------------------------
# Node versions
# ---------------------------------------------------------------------------
echo "--- Node Versions ---"
for entry in ${CP_NODES} ${WORKER_NODES}; do
    hostname="${entry%%:*}"
    ip="${entry##*:}"
    version=$(talosctl version \
        --talosconfig "${TALOSCONFIG}" \
        --nodes "${ip}" \
        --short 2>/dev/null || echo "unreachable")
    printf "  %-20s %-16s %s\n" "${hostname}" "${ip}" "${version}"
done
echo ""

# ---------------------------------------------------------------------------
# Kubernetes status
# ---------------------------------------------------------------------------
echo "--- Kubernetes Status ---"
if [[ -f "${S3_DIR}/configs/kubeconfig" ]]; then
    export KUBECONFIG="${S3_DIR}/configs/kubeconfig"
    echo "Nodes:"
    kubectl get nodes -o wide 2>/dev/null || echo "  kubectl unavailable or cluster not ready"
    echo ""
    echo "System Pods:"
    kubectl get pods -n kube-system -o wide 2>/dev/null || echo "  kubectl unavailable or cluster not ready"
else
    echo "  Kubeconfig not found. Run 'make bootstrap' first."
fi

echo ""
echo "============================================================"
if [[ "${HEALTH_FAILED}" -eq 1 ]]; then
    echo "  HEALTH CHECK FAILED"
    echo "============================================================"
    exit 1
fi
echo "  HEALTH CHECK COMPLETE"
echo "============================================================"
