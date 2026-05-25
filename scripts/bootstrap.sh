#!/usr/bin/env bash
# =============================================================================
# bootstrap.sh — Bootstrap the Talos cluster
#
# This script should only be run ONCE during initial cluster creation.
# It bootstraps etcd on the first control plane node, waits for health,
# and fetches the kubeconfig.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${ROOT_DIR}/cluster/config.env"

S3_DIR="${ROOT_DIR}/${LOCAL_S3_DIR}"
TALOSCONFIG="${S3_DIR}/configs/talosconfig"
BOOTSTRAP_HOSTNAME="${BOOTSTRAP_NODE%%:*}"
BOOTSTRAP_IP="${BOOTSTRAP_NODE##*:}"

# ---------------------------------------------------------------------------
# Safety gate
# ---------------------------------------------------------------------------
echo "============================================================"
echo "  TALOS CLUSTER BOOTSTRAP"
echo "============================================================"
echo ""
echo "  Cluster:        ${CLUSTER_NAME}"
echo "  Bootstrap node: ${BOOTSTRAP_HOSTNAME} (${BOOTSTRAP_IP})"
echo "  Kubernetes:     ${KUBERNETES_VERSION}"
echo ""
echo "  WARNING: This should only be run ONCE during initial"
echo "  cluster creation. Running it again may cause issues."
echo ""
read -p "  Type 'yes' to proceed: " confirm
if [[ "${confirm}" != "yes" ]]; then
    echo "  Aborted."
    exit 1
fi

# ---------------------------------------------------------------------------
# Bootstrap etcd
# ---------------------------------------------------------------------------
echo ""
echo "==> Bootstrapping etcd on ${BOOTSTRAP_HOSTNAME}..."
talosctl bootstrap \
    --talosconfig "${TALOSCONFIG}" \
    --nodes "${BOOTSTRAP_IP}"

# ---------------------------------------------------------------------------
# Wait for health
# ---------------------------------------------------------------------------
echo "==> Waiting for cluster health (up to 10 minutes)..."

# Build node lists for health check
CP_IPS=""
WORKER_IPS=""
for entry in ${CP_NODES}; do
    ip="${entry##*:}"
    CP_IPS="${CP_IPS:+${CP_IPS},}${ip}"
done
for entry in ${WORKER_NODES}; do
    ip="${entry##*:}"
    WORKER_IPS="${WORKER_IPS:+${WORKER_IPS},}${ip}"
done

talosctl health \
    --talosconfig "${TALOSCONFIG}" \
    --nodes "${BOOTSTRAP_IP}" \
    --control-plane-nodes "${CP_IPS}" \
    --worker-nodes "${WORKER_IPS}" \
    --wait-timeout 10m

# ---------------------------------------------------------------------------
# Fetch kubeconfig
# ---------------------------------------------------------------------------
echo "==> Fetching kubeconfig..."
talosctl kubeconfig \
    --talosconfig "${TALOSCONFIG}" \
    --nodes "${BOOTSTRAP_IP}" \
    --force \
    "${S3_DIR}/configs/kubeconfig"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  CLUSTER BOOTSTRAPPED SUCCESSFULLY"
echo "============================================================"
echo ""
echo "  Kubeconfig: ${S3_DIR}/configs/kubeconfig"
echo ""
echo "  To start using the cluster:"
echo "    export KUBECONFIG=${S3_DIR}/configs/kubeconfig"
echo "    kubectl get nodes"
echo ""
echo "  Don't forget to push secrets to S3:"
echo "    make s3-push"
echo ""
