#!/usr/bin/env bash
# =============================================================================
# etcd-snapshot.sh — capture an etcd snapshot from a CP node and upload it
# to S3 with KMS encryption.
#
# Talos's `talosctl etcd snapshot` streams the bbolt DB representing every
# in-cluster K8s object (CRDs, Helm release tracking, RBAC, namespaces,
# Service accounts, every Longhorn volume reference) plus etcd's own
# metadata. Combined with the secrets bundle (.s3/secrets/secrets.yaml,
# already mirrored in S3) this is everything needed to recover the cluster
# after a CP-quorum failure via `talosctl bootstrap --recover-from`.
#
# Source CP selection: prefers a non-bootstrap CP so the bootstrap node is
# never the only one carrying recent snapshot load. Falls back to the
# bootstrap CP only if no non-bootstrap CP is reachable.
#
# S3 layout:
#   s3://${S3_BUCKET}/${S3_PREFIX}etcd-snapshots/YYYY-MM-DD/snapshot-HHMMSSZ.db
#
# Date directories make rotation/inspection easy; the timestamp suffix
# accommodates multiple snapshots per day (e.g., manual taken alongside
# the scheduled daily). KMS encryption matches the existing `secrets/`
# objects in the same bucket.
#
# Exits 0 on successful upload, non-zero on any failure. Implements the
# scheduled-snapshot leg of ADR-0006.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

source cluster/config.env

S3_DIR="${LOCAL_S3_DIR}"
TALOSCONFIG="${S3_DIR}/configs/talosconfig"

if [[ ! -f "${TALOSCONFIG}" ]]; then
    echo "ERROR: talosconfig not found at ${TALOSCONFIG}. Run 'make s3-pull' first." >&2
    exit 2
fi

# --- Choose source CP --------------------------------------------------------
BOOTSTRAP_HOSTNAME="${BOOTSTRAP_NODE%%:*}"
declare -A CP_IP=()
declare -a CP_ORDER=()
for entry in ${CP_NODES}; do
    h="${entry%%:*}"; ip="${entry##*:}"
    CP_IP["${h}"]="${ip}"
    CP_ORDER+=("${h}")
done

# Build a probe list: non-bootstrap first, then bootstrap as fallback.
PROBE_LIST=()
for h in "${CP_ORDER[@]}"; do
    [[ "${h}" != "${BOOTSTRAP_HOSTNAME}" ]] && PROBE_LIST+=("${h}")
done
PROBE_LIST+=("${BOOTSTRAP_HOSTNAME}")

SOURCE_NODE=""
for h in "${PROBE_LIST[@]}"; do
    ip="${CP_IP[${h}]}"
    if timeout 10 talosctl --talosconfig "${TALOSCONFIG}" --nodes "${ip}" version --short >/dev/null 2>&1; then
        SOURCE_NODE="${h}"
        SOURCE_IP="${ip}"
        break
    fi
done

if [[ -z "${SOURCE_NODE}" ]]; then
    echo "ERROR: no reachable CP node for snapshot" >&2
    exit 2
fi

# --- Take the snapshot -------------------------------------------------------
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

DATE_DIR="$(date -u +%Y-%m-%d)"
TIMESTAMP="$(date -u +%H%M%SZ)"
SNAPSHOT_LOCAL="${TMP_DIR}/snapshot.db"

echo "==> etcd snapshot from ${SOURCE_NODE} (${SOURCE_IP}) → ${SNAPSHOT_LOCAL}"
talosctl --talosconfig "${TALOSCONFIG}" --nodes "${SOURCE_IP}" \
    etcd snapshot "${SNAPSHOT_LOCAL}"

if [[ ! -s "${SNAPSHOT_LOCAL}" ]]; then
    echo "ERROR: snapshot file empty or missing: ${SNAPSHOT_LOCAL}" >&2
    exit 2
fi

BYTES=$(stat -c%s "${SNAPSHOT_LOCAL}" 2>/dev/null || wc -c <"${SNAPSHOT_LOCAL}")
echo "    snapshot size: ${BYTES} bytes"

# --- Upload to S3 ------------------------------------------------------------
S3_KEY="${S3_PREFIX}etcd-snapshots/${DATE_DIR}/snapshot-${TIMESTAMP}.db"
S3_URI="s3://${S3_BUCKET}/${S3_KEY}"

echo "==> Uploading to ${S3_URI}"
aws s3 cp "${SNAPSHOT_LOCAL}" "${S3_URI}" \
    --sse aws:kms \
    --metadata "source-node=${SOURCE_NODE},source-ip=${SOURCE_IP},cluster=${CLUSTER_NAME},talos-version=${TALOS_VERSION},k8s-version=${KUBERNETES_VERSION}"

# Verify the object landed
if ! aws s3api head-object --bucket "${S3_BUCKET}" --key "${S3_KEY}" >/dev/null 2>&1; then
    echo "ERROR: post-upload head-object failed for ${S3_URI}" >&2
    exit 2
fi

echo "==> Done. ${BYTES} bytes at ${S3_URI}"
