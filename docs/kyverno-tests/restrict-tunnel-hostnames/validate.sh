#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
POLICY="${REPO_ROOT}/clusters/talos-cluster/apps/kyverno/policies/restrict-tunnel-hostnames.yaml"
VALUES="${TEST_DIR}/fixtures/values.yaml"
KYVERNO_VERSION="v1.18.2"
KYVERNO_SHA256="cb2feb8356149fd2fe774c894ccf0969f4a60a83867dd913af724f74ffbbc18b"

for command_name in curl python3 rg sha256sum tar; do
  command -v "${command_name}" >/dev/null || {
    echo "ERROR: required command not found: ${command_name}" >&2
    exit 2
  }
done

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "ERROR: this checksum-pinned runner supports Linux x86_64" >&2
  exit 2
fi

python3 - "${POLICY}" <<'PY'
import pathlib
import sys

import yaml

path = pathlib.Path(sys.argv[1])
raw = path.read_text(encoding="utf-8")
documents = list(yaml.safe_load_all(raw))
if len(documents) != 1:
    raise SystemExit("static guard: expected exactly one policy document")

policy = documents[0]
if (policy.get("apiVersion"), policy.get("kind"), policy.get("metadata", {}).get("name")) != (
    "policies.kyverno.io/v1",
    "ValidatingPolicy",
    "restrict-tunnel-hostnames",
):
    raise SystemExit("static guard: policy identity changed")

spec = policy.get("spec", {})
expected_common = {
    "validationActions": ["Deny"],
    "failurePolicy": "Fail",
    "evaluation": {"background": {"enabled": False}},
    "webhookConfiguration": {"timeoutSeconds": 5},
}
for key, expected in expected_common.items():
    if spec.get(key) != expected:
        raise SystemExit(f"static guard: spec.{key} must remain {expected!r}")

rules = spec.get("matchConstraints", {}).get("resourceRules")
if rules != [{
    "apiGroups": ["networking.k8s.io"],
    "apiVersions": ["v1"],
    "operations": ["CREATE", "UPDATE"],
    "resources": ["ingresses"],
}]:
    raise SystemExit("static guard: policy must match only Ingress CREATE+UPDATE")

required_fragments = (
    "'nwarila.io/org' in namespaceObject.metadata.labels",
    "!('kubernetes.io/ingress.class' in object.metadata.annotations)",
    "object.spec.ingressClassName == 'cf-tunnel-hwg'",
    "path.backend.service.port.number == 8080",
    "!key.startsWith('traefik.ingress.kubernetes.io/')",
    "!key.startsWith('traefik.io/')",
)
for fragment in required_fragments:
    if fragment not in raw:
        raise SystemExit(f"static guard: missing contract fragment: {fragment}")

print("OK: static hostname/backend policy guard")
PY

RUNNER_TMP="$(mktemp -d "${REPO_ROOT}/.kyverno-cli.XXXXXX")"
trap 'rm -rf -- "${RUNNER_TMP}"' EXIT

KYVERNO_ARCHIVE="${RUNNER_TMP}/kyverno-cli_${KYVERNO_VERSION}_linux_x86_64.tar.gz"
KYVERNO_URL="https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/$(basename "${KYVERNO_ARCHIVE}")"
curl --proto '=https' --tlsv1.2 -4 \
  --retry 5 --retry-all-errors --retry-delay 3 \
  --connect-timeout 20 --max-time 300 -fsSL \
  -o "${KYVERNO_ARCHIVE}" "${KYVERNO_URL}"
echo "${KYVERNO_SHA256}  ${KYVERNO_ARCHIVE}" | sha256sum -c -
tar -xzf "${KYVERNO_ARCHIVE}" -C "${RUNNER_TMP}" kyverno
chmod +x "${RUNNER_TMP}/kyverno"
KYVERNO="${RUNNER_TMP}/kyverno"

"${KYVERNO}" version | rg -Fx "Version: ${KYVERNO_VERSION#v}" >/dev/null || {
  echo "ERROR: downloaded Kyverno CLI did not report ${KYVERNO_VERSION}" >&2
  exit 2
}

case_count=0
run_case() {
  local fixture="$1"
  local expected_result="$2"
  local expected_message="$3"
  local output
  local status
  local report_file="${RUNNER_TMP}/report.json"

  if output="$("${KYVERNO}" apply "${POLICY}" \
      --resource "${TEST_DIR}/fixtures/${fixture}" \
      --values-file "${VALUES}" \
      --policy-report --output-format json --remove-color 2>&1)"; then
    status=0
  else
    status=$?
  fi

  if [[ "${expected_result}" == "unaffected" ]]; then
    if [[ ${status} -ne 0 || -n "${output}" ]]; then
      echo "FAIL: ${fixture}: expected no policy result" >&2
      [[ -n "${output}" ]] && echo "${output}" >&2
      return 1
    fi
  else
    printf '%s' "${output}" >"${report_file}"
    python3 - "${fixture}" "${expected_result}" "${expected_message}" \
      "${status}" "${report_file}" <<'PY'
import json
import sys

fixture, expected_result, expected_message, status_text, report_path = sys.argv[1:]
status = int(status_text)
with open(report_path, encoding="utf-8") as handle:
    report = json.load(handle)

expected_status = 0 if expected_result == "pass" else 1
if status != expected_status:
    raise SystemExit(f"FAIL: {fixture}: exit {status}, expected {expected_status}")
results = report.get("results", [])
if len(results) != 1:
    raise SystemExit(f"FAIL: {fixture}: expected one result, got {len(results)}")
actual = (results[0].get("result"), results[0].get("policy"), results[0].get("message"))
expected = (expected_result, "restrict-tunnel-hostnames", expected_message)
if actual != expected:
    raise SystemExit(f"FAIL: {fixture}: got {actual!r}, expected {expected!r}")
PY
  fi

  case_count=$((case_count + 1))
  echo "OK: ${fixture}: ${expected_result}"
}

run_case "admit/numeric-8080.yaml" "pass" "success"

run_case "deny/out-of-zone.yaml" "fail" \
  "tunnel Ingress hosts must be inside theherowarsguys.com"
run_case "deny/apex.yaml" "fail" \
  "the bare theherowarsguys.com apex is reserved"
run_case "deny/canary.yaml" "fail" \
  "canary-hwg.theherowarsguys.com is reserved"
run_case "deny/wildcard.yaml" "fail" \
  "wildcard tunnel Ingress hosts are not permitted"
run_case "deny/no-rules.yaml" "fail" \
  "tunnel Ingress must declare at least one rule"
run_case "deny/missing-host.yaml" "fail" \
  "every tunnel Ingress rule must declare a host"
run_case "deny/default-backend.yaml" "fail" \
  "tunnel Ingress must not declare spec.defaultBackend"
run_case "deny/tls.yaml" "fail" \
  "tunnel Ingress must not declare spec.tls"
run_case "deny/provider-annotation.yaml" "fail" \
  "Traefik provider annotations are not permitted"
run_case "deny/non-8080.yaml" "fail" \
  "every tunnel Ingress backend must be a Service on numeric port 8080"
run_case "deny/named-port.yaml" "fail" \
  "every tunnel Ingress backend must be a Service on numeric port 8080"
run_case "deny/resource-backend.yaml" "fail" \
  "every tunnel Ingress backend must be a Service on numeric port 8080"
run_case "deny/no-paths.yaml" "fail" \
  "every tunnel Ingress rule must declare at least one HTTP path"

run_case "unaffected/wrong-class.yaml" "pass" "success"
run_case "unaffected/missing-class.yaml" "pass" "success"
run_case "unaffected/legacy-annotation.yaml" "pass" "success"

echo "PASS: ${case_count} restrict-tunnel-hostnames fixtures"
