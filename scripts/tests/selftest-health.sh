#!/usr/bin/env bash
# Stub-based self-test for scripts/health.sh: talosctl, kubectl and helm are exported functions that
# answer from per-case fixture files, so every gate health.sh applies (talosctl health, node count and
# readiness, pod readiness, release status and inventory, each Keycloak operand) is shown to turn the
# run red on its own, a failed read included — and an all-good fixture to end "Platform healthy.".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
HEALTH="${ROOT_DIR}/scripts/health.sh"
command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 1; }

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT:?}"' EXIT

talosctl() {
    printf 'talosctl %s\n' "$*" >> "${CASE_DIR}/calls.log"
    [[ ! -f "${CASE_DIR}/talos-fail" ]] || { echo 'healthcheck error: etcd members not healthy' >&2; return 1; }
}
kubectl() {
    local all="$*" kind name field value
    printf 'kubectl %s\n' "${all}" >> "${CASE_DIR}/calls.log"
    case "${all}" in
        "get nodes -o json") cat "${CASE_DIR}/nodes.json"; return 0 ;;
        "get pods -A -o json") cat "${CASE_DIR}/pods.json"; return 0 ;;
        "get jobs -A -o json") if [[ -f "${CASE_DIR}/jobs.json" ]]; then cat "${CASE_DIR}/jobs.json"; else echo '{"items":[]}'; fi; return 0 ;;
        "get nodes -o wide" | "get pods -A") echo "(listing)"; return 0 ;;
    esac
    # Operand reads: [-n NS] get KIND NAME -o jsonpath=...
    set -- "$@"
    [[ "$1" == "-n" ]] && shift 2
    [[ "$1" == get ]] || { echo "selftest kubectl: unexpected call: ${all}" >&2; return 2; }
    kind="$2"; name="$3"
    case "${all}" in
        *readyInstances*) field=readyInstances ;;
        *'.status.phase'*) field=phase ;;
        *HasErrors*) field=HasErrors ;;
        *'"Done"'*) field=Done ;;
        *'"Ready"'*) field=Ready ;;
        *'"Available"'*) field=Available ;;
        *) echo "selftest kubectl: unexpected jsonpath: ${all}" >&2; return 2 ;;
    esac
    if [[ -f "${CASE_DIR}/fail-${kind}-${name}-${field}" ]]; then
        echo "Error from server (Forbidden): ${kind}s \"${name}\" is forbidden" >&2; return 1
    fi
    if [[ -f "${CASE_DIR}/value-${kind}-${name}-${field}" ]]; then cat "${CASE_DIR}/value-${kind}-${name}-${field}"; return 0; fi
    case "${field}" in
        readyInstances) value=2 ;;
        phase) value="Cluster in healthy state" ;;
        HasErrors) value=False ;;
        *) value=True ;;
    esac
    printf '%s' "${value}"
}
helm() {
    printf 'helm %s\n' "$*" >> "${CASE_DIR}/calls.log"
    case "$*" in
        "list -A --all --max 256 --offset 0 -o json") cat "${CASE_DIR}/releases.json" ;;
        "list -A") echo "(releases)" ;;
        *) echo "selftest helm: unexpected call: $*" >&2; return 2 ;;
    esac
}
export -f talosctl kubectl helm

fixtures() {  # the all-good cluster: six Ready nodes, ready pods, the six expected releases deployed
    jq -n '{items: [range(0; 6) | {metadata: {name: "node\(.)"}, status: {conditions: [{type: "Ready", status: "True"}]}}]}' > "${CASE_DIR}/nodes.json"
    jq -n '{items: [
        {metadata: {namespace: "keycloak", name: "keycloak-0"}, status: {phase: "Running",
         containerStatuses: [{name: "keycloak", ready: true}], conditions: [{type: "Ready", status: "True"}]}},
        {metadata: {namespace: "vault", name: "vault-unsealer-1"}, status: {phase: "Succeeded"}}]}' > "${CASE_DIR}/pods.json"
    jq -n '[
        {name: "calico", namespace: "tigera-operator", status: "deployed"},
        {name: "longhorn", namespace: "longhorn-system", status: "deployed"},
        {name: "argocd", namespace: "argocd", status: "deployed"},
        {name: "vault", namespace: "vault", status: "deployed"},
        {name: "cert-manager", namespace: "cert-manager", status: "deployed"},
        {name: "cnpg", namespace: "keycloak", status: "deployed"}]' > "${CASE_DIR}/releases.json"
}

passed=0
failed=0
# run_case NAME WANT_RC WANT_TEXT SETUP...: SETUP runs in the case directory after the all-good fixtures.
run_case() {
    local name="$1" want_rc="$2" want="$3" rc
    shift 3
    CASE_DIR="${TEST_ROOT}/${name}"; export CASE_DIR
    mkdir -p "${CASE_DIR}"
    fixtures
    (cd "${CASE_DIR}" && "$@")
    set +e
    STATE_DIR_OVERRIDE="${CASE_DIR}" KUBECONFIG="${CASE_DIR}/kubeconfig" timeout 60 bash "${HEALTH}" > "${CASE_DIR}/out" 2>&1
    rc=$?
    set -e
    if [[ "${rc}" == "${want_rc}" ]] && grep -qF -- "${want}" "${CASE_DIR}/out"; then
        passed=$((passed + 1)); printf 'ok   %-40s rc=%s\n' "${name}" "${rc}"
    else
        failed=$((failed + 1)); printf 'FAIL %-40s rc=%s want=%s (%s)\n' "${name}" "${rc}" "${want_rc}" "${want}"
        sed 's/^/    | /' "${CASE_DIR}/out" | tail -8
    fi
}
nothing() { :; }
set_value() { printf '%s' "$2" > "value-$1"; }
set_fail() { : > "fail-$1"; }
drop_release() { jq --arg n "$1" '[.[] | select(.name != $n)]' releases.json > r.tmp && mv r.tmp releases.json; }
release_status() { jq --arg n "$1" --arg s "$2" '[.[] | if .name == $n then .status = $s else . end]' releases.json > r.tmp && mv r.tmp releases.json; }
node_not_ready() { jq '.items[2].status.conditions[0].status = "False"' nodes.json > n.tmp && mv n.tmp nodes.json; }
node_missing() { jq '.items |= .[0:5]' nodes.json > n.tmp && mv n.tmp nodes.json; }
pod_not_ready() { jq '.items[0].status.containerStatuses[0].ready = false | .items[0].status.conditions[0].status = "False"' pods.json > p.tmp && mv p.tmp pods.json; }
talos_fails() { : > talos-fail; }

run_case all-good 0 "Platform healthy." nothing
run_case talos-health-fails 1 "etcd members not healthy" talos_fails
run_case node-not-ready 1 "ERROR: node node2 Ready=False" node_not_ready
run_case node-count-short 1 "ERROR: expected 6 nodes, found 5" node_missing
run_case pod-not-ready 1 "ERROR: pod keycloak/keycloak-0 phase=Running Ready=False" pod_not_ready
run_case release-cnpg-missing 1 "ERROR: expected deployed release keycloak/cnpg exactly once, found 0" drop_release cnpg
run_case release-cert-manager-missing 1 "ERROR: expected deployed release cert-manager/cert-manager exactly once, found 0" drop_release cert-manager
run_case release-failed 1 "ERROR: release keycloak/cnpg status=failed" release_status cnpg failed
run_case operand-read-fails 1 "ERROR: Keycloak keycloak Ready: cannot read" set_fail keycloak-keycloak-Ready
run_case operand-missing 1 "ERROR: Certificate keycloak-tls Ready: missing (want True)" set_value certificate-keycloak-tls-Ready ""
run_case operand-false 1 "ERROR: ClusterIssuer vault-tcn-server Ready: False (want True)" set_value clusterissuer-vault-tcn-server-Ready False
run_case operand-db-one-ready 1 "ERROR: database cluster keycloak-db instances ready: 1 (want 2)" set_value cluster-keycloak-db-readyInstances 1
run_case operand-db-phase 1 "ERROR: database cluster keycloak-db healthy: Setting up primary (want Cluster in healthy state)" set_value cluster-keycloak-db-phase "Setting up primary"
run_case operand-import-errors 1 "ERROR: realm import tcn without errors: True (want False)" set_value keycloakrealmimport-tcn-HasErrors True
run_case operand-import-not-done 1 "ERROR: realm import tcn Done: False (want True)" set_value keycloakrealmimport-tcn-Done False
run_case operand-operator-unavailable 1 "ERROR: keycloak-operator Deployment available: False (want True)" set_value deployment-keycloak-operator-Available False
run_case operand-cnpg-read-fails 1 "ERROR: cnpg operator Deployment available: cannot read" set_fail deployment-cnpg-cloudnative-pg-Available
run_case operand-cloudflared-missing 1 "ERROR: cloudflared Deployment available: missing (want True)" set_value deployment-cloudflared-Available ""

# A failed read must not be followed by a green verdict: the operand-read-fails output must not end healthy.
if grep -qF "Platform healthy." "${TEST_ROOT}/operand-read-fails/out"; then
    failed=$((failed + 1)); echo "FAIL operand-read-fails printed 'Platform healthy.'"
else
    passed=$((passed + 1)); printf 'ok   %-40s\n' "read-failure-never-healthy"
fi

total=$((passed + failed))
if (( failed > 0 )); then
    echo "Self-test FAILED: ${passed}/${total} health cases passed, ${failed} failed."
    exit 1
fi
echo "All ${total} health self-tests passed."
