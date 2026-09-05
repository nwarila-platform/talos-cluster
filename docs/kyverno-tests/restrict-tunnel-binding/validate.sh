#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../../.." && pwd)"
POLICY="${REPO_ROOT}/clusters/talos-cluster/apps/kyverno/policies/restrict-tunnel-binding.yaml"
VALUES="${TEST_DIR}/fixtures/values.yaml"
KYVERNO_VERSION="v1.18.2"
KYVERNO_SHA256="cb2feb8356149fd2fe774c894ccf0969f4a60a83867dd913af724f74ffbbc18b"

for command_name in curl python3 sha256sum tar; do
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

policy_path = pathlib.Path(sys.argv[1])
raw = policy_path.read_text(encoding="utf-8")
documents = list(yaml.safe_load_all(raw))

if len(documents) != 1:
    raise SystemExit("static guard: expected exactly one ValidatingPolicy document")

by_name = {document.get("metadata", {}).get("name"): document for document in documents}
expected_names = {"restrict-tunnel-binding"}
if set(by_name) != expected_names:
    raise SystemExit(f"static guard: policy names changed: {sorted(by_name)}")

for name, document in by_name.items():
    if document.get("apiVersion") != "policies.kyverno.io/v1":
        raise SystemExit(f"static guard: {name} must use policies.kyverno.io/v1")
    if document.get("kind") != "ValidatingPolicy":
        raise SystemExit(f"static guard: {name} must remain a ValidatingPolicy")

    spec = document.get("spec", {})
    expected_common = {
        "validationActions": ["Deny"],
        "failurePolicy": "Fail",
        "evaluation": {"background": {"enabled": False}},
        "webhookConfiguration": {"timeoutSeconds": 5},
    }
    for field, expected in expected_common.items():
        if spec.get(field) != expected:
            raise SystemExit(
                f"static guard: {name} spec.{field} must remain {expected!r}"
            )

    match_constraints = spec.get("matchConstraints", {})
    if match_constraints.get("matchPolicy") != "Equivalent":
        raise SystemExit(f"static guard: {name} matchPolicy must remain Equivalent")
    if "excludeResourceRules" in match_constraints:
        raise SystemExit(f"static guard: {name} must not declare excludeResourceRules")

for forbidden in ("cluster-admin", "system:masters", "userInfo", "authorizer"):
    if forbidden in raw:
        raise SystemExit(f"static guard: forbidden actor bypass marker found: {forbidden}")

binding = by_name["restrict-tunnel-binding"]
binding_match = binding["spec"]["matchConstraints"]
if binding_match.get("namespaceSelector") != {
    "matchLabels": {"nwarila.io/tenant": "true"}
}:
    raise SystemExit("static guard: tenant namespaceSelector changed")

expected_binding_rules = [
    {
        "apiGroups": ["networking.k8s.io"],
        "apiVersions": ["v1"],
        "operations": ["CREATE", "UPDATE"],
        "resources": ["ingresses"],
    },
    {
        "apiGroups": ["networking.k8s.io"],
        "apiVersions": ["v1"],
        "operations": ["UPDATE"],
        "resources": ["ingresses/status"],
    },
    {
        "apiGroups": ["networking.k8s.io"],
        "apiVersions": ["v1"],
        "operations": ["CREATE", "UPDATE"],
        "resources": ["ingressclasses"],
    },
]
if binding_match.get("resourceRules") != expected_binding_rules:
    raise SystemExit(
        "static guard: ingresses must keep CREATE+UPDATE and "
        "ingresses/status must keep UPDATE"
    )

messages = [entry.get("message") for entry in binding["spec"].get("validations", [])]
expected_precedence = [
    "namespace has no registered tunnel binding",
    "the deprecated ingress-class annotation is not permitted",
    "tenant Ingress must use its registered tunnel ingress class",
    "cf-tunnel-* IngressClasses must not be marked as default",
]
if messages != expected_precedence:
    raise SystemExit("static guard: validation precedence must remain a -> c -> b")

print("OK: static policy guard (no actor bypass; ingress CREATE+UPDATE; status UPDATE; a->c->b)")
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

version_output="$("${KYVERNO}" version)"
grep -Fx "Version: ${KYVERNO_VERSION#v}" <<<"${version_output}" >/dev/null || {
  echo "ERROR: downloaded Kyverno CLI did not report ${KYVERNO_VERSION}" >&2
  exit 2
}

case_count=0

run_case() {
  local fixture="$1"
  local expected_result="$2"
  local expected_policy="$3"
  local expected_message="$4"
  local output
  local report_file
  local status

  if output="$("${KYVERNO}" apply "${POLICY}" \
      --resource "${TEST_DIR}/fixtures/${fixture}" \
      --values-file "${VALUES}" \
      --policy-report \
      --output-format json \
      --remove-color 2>&1)"; then
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
    report_file="${RUNNER_TMP}/report.json"
    printf '%s' "${output}" >"${report_file}"
    python3 - "${fixture}" "${expected_result}" "${expected_policy}" \
      "${expected_message}" "${status}" "${report_file}" <<'PY'
import json
import sys

fixture, expected_result, expected_policy, expected_message, status_text, report_path = sys.argv[1:]
status = int(status_text)

try:
    with open(report_path, encoding="utf-8") as handle:
        report = json.load(handle)
except (json.JSONDecodeError, UnicodeDecodeError) as error:
    raise SystemExit(f"FAIL: {fixture}: invalid Kyverno JSON: {error}") from error

expected_status = 0 if expected_result == "pass" else 1
if status != expected_status:
    raise SystemExit(
        f"FAIL: {fixture}: exit status {status}, expected {expected_status}"
    )

results = report.get("results", [])
if len(results) != 1:
    raise SystemExit(f"FAIL: {fixture}: expected exactly one result, got {len(results)}")

result = results[0]
actual = (result.get("result"), result.get("policy"), result.get("message"))
expected = (expected_result, expected_policy, expected_message)
if actual != expected:
    raise SystemExit(f"FAIL: {fixture}: got {actual!r}, expected {expected!r}")

summary = report.get("summary", {})
expected_summary = {"pass": 0, "fail": 0, "warn": 0, "error": 0, "skip": 0}
expected_summary[expected_result] = 1
if summary != expected_summary:
    raise SystemExit(
        f"FAIL: {fixture}: summary {summary!r}, expected {expected_summary!r}"
    )
PY
  fi

  case_count=$((case_count + 1))
  echo "OK: ${fixture}: ${expected_result}"
}

run_case "admit/hwg-own.yaml" "pass" "restrict-tunnel-binding" "success"
run_case "admit/nwp-own.yaml" "pass" "restrict-tunnel-binding" "success"
run_case "admit/nwp-mtls-own.yaml" "pass" "restrict-tunnel-binding" "success"

run_case "deny/hwg-cross-org.yaml" "fail" "restrict-tunnel-binding" \
  "namespace hwg-1268831311 permits only ingress class cf-tunnel-hwg; requested cf-tunnel-nwp-public"
run_case "deny/nwp-cross-org.yaml" "fail" "restrict-tunnel-binding" \
  "namespace nwp-1306985678 permits only ingress classes cf-tunnel-nwp-public, cf-tunnel-nwp-mtls; requested cf-tunnel-hwg"
run_case "deny/nwp-class-retired.yaml" "fail" "restrict-tunnel-binding" \
  "namespace nwp-1306985678 permits only ingress classes cf-tunnel-nwp-public, cf-tunnel-nwp-mtls; requested cf-tunnel-nwp"
run_case "deny/hwg-class-absent.yaml" "fail" "restrict-tunnel-binding" \
  "namespace hwg-1268831311 permits only ingress class cf-tunnel-hwg; requested <absent>"
run_case "deny/hwg-class-suffix.yaml" "fail" "restrict-tunnel-binding" \
  "namespace hwg-1268831311 permits only ingress class cf-tunnel-hwg; requested cf-tunnel-hwg2"
run_case "deny/hwg-class-dot-suffix.yaml" "fail" "restrict-tunnel-binding" \
  "namespace hwg-1268831311 permits only ingress class cf-tunnel-hwg; requested cf-tunnel-hwg.evil"
run_case "deny/hwg-class-prefixed.yaml" "fail" "restrict-tunnel-binding" \
  "namespace hwg-1268831311 permits only ingress class cf-tunnel-hwg; requested x-cf-tunnel-hwg"
run_case "deny/hwg-class-extra.yaml" "fail" "restrict-tunnel-binding" \
  "namespace hwg-1268831311 permits only ingress class cf-tunnel-hwg; requested cf-tunnel-hwg-extra"
run_case "deny/hwg-class-truncated.yaml" "fail" "restrict-tunnel-binding" \
  "namespace hwg-1268831311 permits only ingress class cf-tunnel-hwg; requested cf-tunnel-hw"
run_case "deny/identity-label-absent.yaml" "fail" "restrict-tunnel-binding" \
  "namespace has no registered tunnel binding"
run_case "deny/identity-unregistered.yaml" "fail" "restrict-tunnel-binding" \
  "namespace has no registered tunnel binding"
run_case "deny/legacy-correct.yaml" "fail" "restrict-tunnel-binding" \
  "the deprecated ingress-class annotation is not permitted"
run_case "deny/legacy-cross-org.yaml" "fail" "restrict-tunnel-binding" \
  "the deprecated ingress-class annotation is not permitted"
run_case "deny/legacy-annotation-only.yaml" "fail" "restrict-tunnel-binding" \
  "the deprecated ingress-class annotation is not permitted"
run_case "deny/default-class.yaml" "fail" "restrict-tunnel-binding" \
  "cf-tunnel-* IngressClasses must not be marked as default"

run_case "unaffected/flux-system.yaml" "unaffected" "" ""
run_case "unaffected/cloudflared-hwg.yaml" "unaffected" "" ""

echo "OK: ${case_count} CREATE-only fixtures matched exact policy outcomes and messages"
