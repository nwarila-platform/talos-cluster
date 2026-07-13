#!/usr/bin/env bash
# =============================================================================
# backup-handoff-ledger.sh - Encrypt and stage the local _handoff ledger backup
#
# This runs on the workstation where _handoff/ exists. CI cannot exercise the
# real ledger set because _handoff/ is intentionally gitignored by the deny-all
# policy. The actual S3 write is operator-run and uses ambient AWS credentials.
#
# Plaintext tarballs are created under mktemp and removed immediately after
# encryption. Use a tmpfs-backed TMPDIR when stronger local residue guarantees
# are required; the default /tmp may be disk-backed on some hosts.
#
# Usage:
#   bash scripts/backup-handoff-ledger.sh --dry-run
#   bash scripts/backup-handoff-ledger.sh [--keep-local DIR]
# =============================================================================
set -euo pipefail

readonly AGE_RECIPIENT="age1eqgtee0na7sw2mez3xa7jh2wyy2qkju3jx70g7plxt3g8u3syqtsqxj7m0"

DRY_RUN=false
KEEP_LOCAL_DIR=""
ROOT_DIR="$(pwd -P)"
TMP_DIR=""

usage() {
    cat <<'EOF'
Usage: backup-handoff-ledger.sh [--dry-run] [--keep-local DIR]

  --dry-run         Build and encrypt the ledger snapshot, but skip S3 upload.
  --keep-local DIR  Also copy the encrypted .age artifact into DIR.
EOF
}

fatal() {
    echo "FATAL: $*" >&2
    exit 1
}

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        fatal "required command not found on PATH: ${command_name}"
    fi
}

cleanup() {
    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        rm -rf -- "${TMP_DIR}"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --keep-local)
            shift
            [[ $# -gt 0 ]] || fatal "--keep-local requires a directory"
            KEEP_LOCAL_DIR="$1"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            fatal "unknown argument: $1"
            ;;
    esac
done

[[ -f "${ROOT_DIR}/_handoff/PLAN.md" ]] || \
    fatal "missing _handoff/PLAN.md; run from the repository root with the local ledger set present"
[[ -f "${ROOT_DIR}/_handoff/ROADMAP.md" ]] || \
    fatal "missing _handoff/ROADMAP.md; run from the repository root with the local ledger set present"
[[ -f "${ROOT_DIR}/cluster/config.env" ]] || \
    fatal "missing cluster/config.env; run from the repository root"

require_command tar
require_command age
require_command date
require_command mktemp
require_command rm
require_command sha256sum
require_command stat

if [[ "${DRY_RUN}" != true ]]; then
    require_command aws
fi

# shellcheck source=cluster/config.env
source "${ROOT_DIR}/cluster/config.env"

[[ -n "${S3_BUCKET:-}" ]] || fatal "cluster/config.env must set S3_BUCKET"
[[ -n "${S3_PREFIX:-}" ]] || fatal "cluster/config.env must set S3_PREFIX"

umask 077
trap cleanup EXIT

STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
TMP_DIR="$(mktemp -d)"
TAR_PATH="${TMP_DIR}/handoff-${STAMP}.tar.gz"
AGE_PATH="${TMP_DIR}/handoff-${STAMP}.tar.gz.age"
OBJECT_KEY="${S3_PREFIX%/}/ledger-snapshots/handoff-${STAMP}.tar.gz.age"
S3_URI="s3://${S3_BUCKET}/${OBJECT_KEY}"

echo "Ledger snapshot stamp: ${STAMP}"
echo "Ledger source: ${ROOT_DIR}/_handoff"
echo "S3 object key: ${OBJECT_KEY}"

tar -C "${ROOT_DIR}" -czf "${TAR_PATH}" _handoff
TAR_SIZE="$(stat -c%s "${TAR_PATH}")"
echo "Plaintext tarball size: ${TAR_SIZE} bytes"

age -r "${AGE_RECIPIENT}" -o "${AGE_PATH}" "${TAR_PATH}"
AGE_SIZE="$(stat -c%s "${AGE_PATH}")"
SHA256_LINE="$(sha256sum "${AGE_PATH}")"
AGE_SHA256="${SHA256_LINE%% *}"

rm -f -- "${TAR_PATH}"
if [[ -e "${TAR_PATH}" ]]; then
    fatal "plaintext tarball still exists after removal attempt: ${TAR_PATH}"
fi

echo "Encrypted artifact size: ${AGE_SIZE} bytes"
echo "Encrypted artifact SHA256: ${AGE_SHA256}"
echo "Plaintext tarball removed: yes"

if [[ -n "${KEEP_LOCAL_DIR}" ]]; then
    mkdir -p -- "${KEEP_LOCAL_DIR}"
    KEEP_LOCAL_PATH="${KEEP_LOCAL_DIR%/}/handoff-${STAMP}.tar.gz.age"
    cp -- "${AGE_PATH}" "${KEEP_LOCAL_PATH}"
    echo "Kept encrypted artifact: ${KEEP_LOCAL_PATH}"
fi

if [[ "${DRY_RUN}" == true ]]; then
    echo "Dry run: upload skipped"
    echo "Would upload: ${S3_URI}"
else
    aws s3 cp "${AGE_PATH}" "${S3_URI}" --sse aws:kms
    echo "Uploaded: ${S3_URI}"
fi
