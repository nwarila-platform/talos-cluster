#!/usr/bin/env bash
# =============================================================================
# kubescape-scan.sh — run a Kubescape CIS K8s Benchmark scan against the
# live cluster, upload the JSON report to S3, diff against the in-repo
# baseline.
#
# Implements the continuous-CIS-scanning leg of ADR-0009 §Confirmation §2.
# API-based scanner (no in-cluster Job, no hostPath, no privileged pod) —
# fits Talos's deliberate departures from a conventional Linux file
# layout. See docs/compliance/README.md for the operator-facing
# explanation.
#
# Exits:
#   0 — scan ran, score ≥ baseline (or no baseline yet)
#   1 — scan ran, score regressed against baseline beyond tolerance
#   2 — scan failed to run or upload
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

source cluster/config.env

S3_DIR="${LOCAL_S3_DIR}"
KUBECONFIG_PATH="${S3_DIR}/configs/kubeconfig"
BASELINE_FILE="docs/compliance/kubescape-baseline.json"
# A regression of more than this many points triggers exit 1. Set to 0 for
# strict (any score drop fails); set higher for tolerance to scan-jitter.
REGRESSION_TOLERANCE="1.0"
# Framework to scan. Update only via ADR (changes the compliance contract).
FRAMEWORK="cis-v1.10.0"

if [[ ! -f "${KUBECONFIG_PATH}" ]]; then
    echo "ERROR: kubeconfig missing at ${KUBECONFIG_PATH}; run 'make s3-pull' first" >&2
    exit 2
fi
if ! command -v kubescape >/dev/null 2>&1; then
    echo "ERROR: kubescape CLI not on PATH; install from https://github.com/kubescape/kubescape/releases" >&2
    exit 2
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

SCAN_FILE="${TMP_DIR}/scan.json"

echo "==> Running kubescape scan (framework=${FRAMEWORK})"
kubescape scan framework "${FRAMEWORK}" \
    --kubeconfig "${KUBECONFIG_PATH}" \
    --format json \
    --output "${SCAN_FILE}" \
    --submit=false  # do not send results to the kubescape cloud backend
echo ""

if [[ ! -s "${SCAN_FILE}" ]]; then
    echo "ERROR: kubescape produced empty output" >&2
    exit 2
fi

# Extract the headline score using python (jq not guaranteed on every runner).
SCAN_SCORE=$(python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get('summaryDetails', {}).get('score', 0))
" "${SCAN_FILE}")
echo "==> Scan compliance score: ${SCAN_SCORE}"

# Upload to S3 with KMS encryption (same posture as etcd snapshots)
DATE_DIR="$(date -u +%Y-%m-%d)"
TIMESTAMP="$(date -u +%H%M%SZ)"
S3_KEY="${S3_PREFIX}compliance/kubescape/${DATE_DIR}/scan-${TIMESTAMP}.json"
S3_URI="s3://${S3_BUCKET}/${S3_KEY}"

echo "==> Uploading scan to ${S3_URI}"
aws s3 cp "${SCAN_FILE}" "${S3_URI}" \
    --sse aws:kms \
    --metadata "cluster=${CLUSTER_NAME},framework=${FRAMEWORK},talos-version=${TALOS_VERSION},k8s-version=${KUBERNETES_VERSION},score=${SCAN_SCORE}"

if ! aws s3api head-object --bucket "${S3_BUCKET}" --key "${S3_KEY}" >/dev/null 2>&1; then
    echo "ERROR: post-upload head-object failed for ${S3_URI}" >&2
    exit 2
fi
echo ""

# --- Baseline regression check ----------------------------------------------
if [[ ! -f "${BASELINE_FILE}" ]]; then
    echo "==> No baseline at ${BASELINE_FILE}"
    echo "    This is the cluster's first kubescape run. After operator triage,"
    echo "    commit the scan output as ${BASELINE_FILE} via a PR. Subsequent"
    echo "    runs will diff against it."
    echo ""
    echo "    Latest scan available at: ${S3_URI}"
    exit 0
fi

BASELINE_SCORE=$(python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get('summaryDetails', {}).get('score', 0))
" "${BASELINE_FILE}")
echo "==> Baseline compliance score: ${BASELINE_SCORE}"

REGRESSION=$(python3 -c "
import sys
s = float(sys.argv[1])
b = float(sys.argv[2])
print('1' if (b - s) > float(sys.argv[3]) else '0')
" "${SCAN_SCORE}" "${BASELINE_SCORE}" "${REGRESSION_TOLERANCE}")

if [[ "${REGRESSION}" = "1" ]]; then
    echo "==> REGRESSION: scan score (${SCAN_SCORE}) is more than ${REGRESSION_TOLERANCE} below baseline (${BASELINE_SCORE})"
    echo "    Open a triage cycle: identify the new failure(s), remediate per ADR-0009,"
    echo "    OR add a documented deviation to ADR-0009's table + update the baseline."
    exit 1
fi

echo "==> No regression (score ${SCAN_SCORE} within ${REGRESSION_TOLERANCE} of baseline ${BASELINE_SCORE})"
exit 0
