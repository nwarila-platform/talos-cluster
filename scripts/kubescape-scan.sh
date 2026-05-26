#!/usr/bin/env bash
# =============================================================================
# kubescape-scan.sh — run a Kubescape CIS K8s Benchmark scan against the
# live cluster, convert the JSON output to SARIF for GitHub Code Scanning
# ingestion.
#
# Implements the continuous-CIS-scanning leg of ADR-0009 §Confirmation §2.
# API-based scanner (no in-cluster Job, no hostPath, no privileged pod) —
# fits Talos's deliberate departures from a conventional Linux file
# layout. See docs/compliance/README.md for the operator-facing
# explanation.
#
# Why JSON-then-convert (not --format sarif directly): kubescape v4.0.8's
# native SARIF output is only supported when scanning local files; live
# cluster scans must emit JSON. scripts/kubescape-json-to-sarif.py converts
# the JSON to SARIF 2.1.0 with stable per-finding fingerprints so Code
# Scanning can track Open / Fixed / Dismissed state across runs.
#
# Exits:
#   0 — scan ran, SARIF written
#   2 — scan failed to run (missing kubeconfig, missing CLI, empty output,
#       SARIF conversion failure)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

source cluster/config.env

S3_DIR="${LOCAL_S3_DIR}"
KUBECONFIG_PATH="${S3_DIR}/configs/kubeconfig"
# Framework to scan. Update only via ADR (changes the compliance contract).
FRAMEWORK="cis-v1.10.0"
# Output paths. The workflow uploads SARIF via github/codeql-action/upload-sarif.
# Local runs leave the files in the working tree; .gitignore's deny-all keeps
# them untracked.
SARIF_FILE="${SARIF_FILE:-${ROOT_DIR}/kubescape.sarif}"

if [[ ! -f "${KUBECONFIG_PATH}" ]]; then
    echo "ERROR: kubeconfig missing at ${KUBECONFIG_PATH}; run 'make s3-pull' first" >&2
    exit 2
fi
if ! command -v kubescape >/dev/null 2>&1; then
    echo "ERROR: kubescape CLI not on PATH; install from https://github.com/kubescape/kubescape/releases" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not on PATH; required for SARIF conversion" >&2
    exit 2
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT
JSON_FILE="${TMP_DIR}/scan.json"

echo "==> Running kubescape scan (framework=${FRAMEWORK}, format=json)"
kubescape scan framework "${FRAMEWORK}" \
    --kubeconfig "${KUBECONFIG_PATH}" \
    --format json \
    --output "${JSON_FILE}" \
    --submit=false  # do not send results to the kubescape cloud backend
echo ""

# kubescape on Windows may rewrite the path; resolve the real file location.
if [[ ! -s "${JSON_FILE}" ]]; then
    # Search the temp dir for the produced file (kubescape sometimes adds
    # extension or rewrites paths under Windows MSYS).
    found=$(find "${TMP_DIR}" -type f -name "*.json" -size +0c | head -1)
    if [[ -n "${found}" ]]; then
        JSON_FILE="${found}"
    fi
fi
if [[ ! -s "${JSON_FILE}" ]]; then
    echo "ERROR: kubescape produced empty JSON output (expected at ${TMP_DIR}/scan.json)" >&2
    exit 2
fi

echo "==> Converting JSON to SARIF 2.1.0"
python3 "${SCRIPT_DIR}/kubescape-json-to-sarif.py" "${JSON_FILE}" "${SARIF_FILE}"

if [[ ! -s "${SARIF_FILE}" ]]; then
    echo "ERROR: SARIF conversion produced empty output at ${SARIF_FILE}" >&2
    exit 2
fi

# Final validation: the file is parseable SARIF 2.1.0.
python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get('version', '').startswith('2.1'), f'unexpected SARIF version: {d.get(\"version\")}'
runs = d.get('runs', [])
assert runs, 'SARIF has no runs'
results = sum(len(r.get('results', [])) for r in runs)
print(f'==> SARIF OK: version={d[\"version\"]}, runs={len(runs)}, results={results}')
" "${SARIF_FILE}"

echo ""
echo "==> SARIF written to ${SARIF_FILE}"
echo "    In CI: github/codeql-action/upload-sarif ingests this into Code Scanning."
echo "    Locally: open the Security tab on github.com/<org>/<repo> after the next CI run,"
echo "    or inspect ${SARIF_FILE} with any SARIF viewer."
exit 0
