#!/usr/bin/env bash
# =============================================================================
# s3-sync.sh — Sync local .s3 directory with AWS S3
#
# Usage:
#   ./scripts/s3-sync.sh push   # Upload local → S3
#   ./scripts/s3-sync.sh pull   # Download S3 → local
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${ROOT_DIR}/cluster/config.env"

S3_DIR="${ROOT_DIR}/${LOCAL_S3_DIR}"
S3_URI="s3://${S3_BUCKET}/${S3_PREFIX}"
ACTION="${1:-}"

case "${ACTION}" in
    push)
        echo "==> Pushing local secrets to S3..."
        echo "    Source: ${S3_DIR}/"
        echo "    Dest:   ${S3_URI}"
        echo ""
        # Intentionally additive: no --delete. Local state is not
        # authoritative — `make clean` removes talosconfig/kubeconfig
        # locally, and a sync-with-delete would silently destroy those
        # admin credentials in S3 (potential cluster lockout). To prune
        # orphaned remote objects, run `aws s3 rm` explicitly.
        aws s3 sync "${S3_DIR}/" "${S3_URI}" \
            --sse aws:kms \
            --exclude ".gitkeep"
        echo ""
        echo "==> Push complete."
        ;;
    pull)
        echo "==> Pulling secrets from S3..."
        echo "    Source: ${S3_URI}"
        echo "    Dest:   ${S3_DIR}/"
        echo ""
        mkdir -p "${S3_DIR}/secrets" "${S3_DIR}/configs" \
                 "${S3_DIR}/generated/controlplane" "${S3_DIR}/generated/worker"
        aws s3 sync "${S3_URI}" "${S3_DIR}/" \
            --sse aws:kms
        echo ""
        echo "==> Pull complete."
        ;;
    *)
        echo "Usage: $0 [push|pull]"
        echo ""
        echo "  push  Upload local .s3/ to AWS S3 (encrypted with KMS)"
        echo "  pull  Download from AWS S3 to local .s3/"
        exit 1
        ;;
esac
