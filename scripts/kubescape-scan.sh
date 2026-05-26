#!/usr/bin/env bash
# =============================================================================
# kubescape-scan.sh — run a Kubescape CIS K8s Benchmark scan against the
# live cluster, emit SARIF for GitHub Code Scanning ingestion.
#
# Implements the continuous-CIS-scanning leg of ADR-0009 §Confirmation §2.
# API-based scanner (no in-cluster Job, no hostPath, no privileged pod) —
# fits Talos's deliberate departures from a conventional Linux file
# layout. See docs/compliance/README.md for the operator-facing
# explanation.
#
# Per-finding state (Open / Fixed / Dismissed) is tracked by GitHub Code
# Scanning, not by this script — no baseline JSON, no score-delta math.
# The workflow uploads the SARIF artifact; the Security tab is the triage
# surface.
#
# Exits:
#   0 — scan ran, SARIF written
#   2 — scan failed to run (missing kubeconfig, missing CLI, empty output)
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
# Output path. The workflow uploads this via github/codeql-action/upload-sarif.
# Local runs leave it in the working tree; .gitignore's deny-all keeps it untracked.
SARIF_FILE="${SARIF_FILE:-${ROOT_DIR}/kubescape.sarif}"

if [[ ! -f "${KUBECONFIG_PATH}" ]]; then
    echo "ERROR: kubeconfig missing at ${KUBECONFIG_PATH}; run 'make s3-pull' first" >&2
    exit 2
fi
if ! command -v kubescape >/dev/null 2>&1; then
    echo "ERROR: kubescape CLI not on PATH; install from https://github.com/kubescape/kubescape/releases" >&2
    exit 2
fi

echo "==> Running kubescape scan (framework=${FRAMEWORK}, format=sarif)"
kubescape scan framework "${FRAMEWORK}" \
    --kubeconfig "${KUBECONFIG_PATH}" \
    --format sarif \
    --output "${SARIF_FILE}" \
    --submit=false  # do not send results to the kubescape cloud backend
echo ""

if [[ ! -s "${SARIF_FILE}" ]]; then
    echo "ERROR: kubescape produced empty SARIF output at ${SARIF_FILE}" >&2
    exit 2
fi

# Validate the file is parseable SARIF (catches truncation, format-flag drift).
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
