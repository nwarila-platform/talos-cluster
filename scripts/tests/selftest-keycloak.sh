#!/usr/bin/env bash
# Stub-based self-test for scripts/keycloak.sh: kubectl is replaced by an exported function that
# models config-view, the keycloak-realm-secrets Secret, the Keycloak readiness wait and the
# KeycloakRealmImport lifecycle, so the fresh path, the rerun paths, a mismatching or unreadable
# Secret, malformed state files, an unready server, a failed import and secret hygiene are all
# decidable without a cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"
export CLUSTER_ENDPOINT

for command in jq sha256sum base64 openssl; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT:?}"' EXIT
chmod 0700 "${TEST_ROOT}"
umask 077  # fixtures are written the way the owner's tooling writes them: 0600

ADMIN="selftest-admin-password-0123456789ABCDEFGHIJ"
BIND="selftest-bind-password-0123456789abcdefghij+/="
CLIENT="selftest-client-secret-0123456789ABCDEFGHIJ"

kubectl() {
    local -a args=("$@")
    printf 'kubectl %s\n' "$*" >> "${CASE_DIR}/calls.log"
    case "$*" in
        *"config view"*) printf '%s' "${CLUSTER_ENDPOINT}" ;;
        *"get secret keycloak-realm-secrets --ignore-not-found -o json"*)
            if [[ -f "${CASE_DIR}/get-error" ]]; then
                echo 'Error from server (ServiceUnavailable): the server is currently unable to handle the request' >&2; return 1
            elif [[ -f "${CASE_DIR}/existing-secret.json" ]]; then cat "${CASE_DIR}/existing-secret.json"; fi ;;
        *"create secret generic keycloak-realm-secrets --from-file="*)
            local dir="${args[6]#--from-file=}" f
            for f in "${dir}"/*; do printf 'secret-file %s sha256=%s\n' "${f##*/}" "$(sha256sum "${f}" | cut -c1-64)" >> "${CASE_DIR}/calls.log"; done
            printf 'secret/keycloak-realm-secrets created\n' ;;
        *"get keycloak keycloak -o name"*) printf 'keycloak.k8s.keycloak.org/keycloak\n' ;;
        *"wait keycloak/keycloak --for=condition=Ready"*)
            [[ "${STUB_KC_READY}" == "true" ]] || { echo 'error: timed out waiting for the condition on keycloaks/keycloak' >&2; return 1; }
            printf 'keycloak.k8s.keycloak.org/keycloak condition met\n' ;;
        *"get keycloakrealmimport tcn --ignore-not-found -o json"*)
            if [[ -f "${CASE_DIR}/existing-import.json" ]]; then cat "${CASE_DIR}/existing-import.json"; fi ;;
        *"create --dry-run=server --validate=strict -f "*)
            [[ ! -f "${CASE_DIR}/dry-run-reject" ]] || { echo 'The KeycloakRealmImport "tcn" is invalid: spec.realm.components: Invalid value' >&2; return 1; }
            printf 'keycloakrealmimport.k8s.keycloak.org/tcn created (server dry run)\n' ;;
        *"create -f "*)
            printf 'created %s\n' "${args[2]}" >> "${CASE_DIR}/calls.log"
            printf 'keycloakrealmimport.k8s.keycloak.org/tcn created\n' ;;
        *"get keycloakrealmimport tcn -o json"*)
            # First poll: started; second poll: the configured outcome.
            if [[ ! -f "${CASE_DIR}/polled" ]]; then
                : > "${CASE_DIR}/polled"
                printf '{"status":{"conditions":[{"type":"Started","status":"True"},{"type":"Done","status":"False"},{"type":"HasErrors","status":"False"}]}}'
            elif [[ "${STUB_IMPORT}" == "never" ]]; then
                printf '{"status":{"conditions":[{"type":"Started","status":"True"},{"type":"Done","status":"False"},{"type":"HasErrors","status":"False"}]}}'
            elif [[ "${STUB_IMPORT}" == "errors" ]]; then
                printf '{"status":{"conditions":[{"type":"Started","status":"True"},{"type":"Done","status":"False"},{"type":"HasErrors","status":"True","message":"Realm import job failed"}]}}'
            else
                printf '{"status":{"conditions":[{"type":"Started","status":"True"},{"type":"Done","status":"True"},{"type":"HasErrors","status":"False"}]}}'
            fi ;;
    esac
    return 0
}
export -f kubectl
[[ "$(bash -c 'type -t kubectl')" == "function" ]] || { echo "ERROR: stub export failed" >&2; exit 1; }

PASSED=0; FAILED_CASES=0; CASE_OK=1
EXPECTED_CASES="$(grep -c '^begin_case ' "${BASH_SOURCE[0]}")"
begin_case() {  # begin_case NAME [KC_READY] [IMPORT_OUTCOME]
    CASE_NAME="$1"; CASE_DIR="${TEST_ROOT}/${CASE_NAME}"; STATE="${CASE_DIR}/state"; CASE_OK=1
    export CASE_DIR STUB_KC_READY="${2:-true}" STUB_IMPORT="${3:-done}"
    mkdir -p "${STATE}/configs" "${STATE}/keycloak"; printf 'stub kubeconfig\n' > "${STATE}/configs/kubeconfig"
    : > "${CASE_DIR}/calls.log"; : > "${CASE_DIR}/out"
}
fail() { echo "FAIL ${CASE_NAME}: $1" >&2; CASE_OK=0; }
end_case() { if (( CASE_OK )); then echo "PASS ${CASE_NAME}"; PASSED=$((PASSED + 1)); else FAILED_CASES=$((FAILED_CASES + 1)); fi; }
state_files() {  # the three inputs, as the owner's tooling writes them (single line, no newline)
    printf '%s' "${ADMIN}" > "${STATE}/keycloak/admin.password"
    printf '%s' "${BIND}" > "${STATE}/keycloak/svc-keycloak.password"
    printf '%s' "${CLIENT}" > "${STATE}/keycloak/gitlab-client.secret"
}
run() {  # run EXPECTED_EXIT
    local rc=0
    # A bounded wall clock: a driver that never returns (a lost timeout) fails the case instead of hanging it.
    env -u KUBECONFIG STATE_DIR_OVERRIDE="${STATE}" CONFIRM_REBUILD=TDNHQ-TALCL01 KEYCLOAK_POLL_SECONDS=0 KEYCLOAK_IMPORT_TIMEOUT=2 \
        timeout 60 bash "${ROOT_DIR}/scripts/keycloak.sh" > "${CASE_DIR}/out" 2>&1 || rc=$?
    [[ "${rc}" == "$1" ]] || fail "exit ${rc}, expected $1: $(tail -n 3 "${CASE_DIR}/out" | tr '\n' ' ')"
    local value
    for value in "${ADMIN}" "${BIND}" "${CLIENT}"; do
        ! grep -qF -- "${value}" "${CASE_DIR}/out" || fail "a secret value leaked to output"
        ! grep -qF -- "${value}" "${CASE_DIR}/calls.log" || fail "a secret value appeared in argv"
    done
    local f
    for f in admin.password gitlab-client.secret; do  # values the script generates must be 0600
        if [[ -e "${STATE}/keycloak/${f}" && ! -e "${CASE_DIR}/skip-mode-check" ]]; then
            [[ "$(stat -c %a "${STATE}/keycloak/${f}")" == "600" ]] || fail "${f} is not mode 0600"
        fi
    done
}
expect_calls() { grep -qE -- "$1" "${CASE_DIR}/calls.log" || fail "missing call matching: $1"; }
forbid_calls() { ! grep -qE -- "$1" "${CASE_DIR}/calls.log" || fail "forbidden call matching: $1"; }
expect_output() { grep -qF -- "$1" "${CASE_DIR}/out" || fail "output lacks: $1"; }
expect_secret_files() {  # the Secret was built from exactly the three state files
    expect_calls "^secret-file ADMIN_PASSWORD sha256=$(printf '%s' "${ADMIN}" | sha256sum | cut -c1-64)$"
    expect_calls "^secret-file LDAP_BIND_PASSWORD sha256=$(printf '%s' "${BIND}" | sha256sum | cut -c1-64)$"
    expect_calls "^secret-file GITLAB_CLIENT_SECRET sha256=$(printf '%s' "${CLIENT}" | sha256sum | cut -c1-64)$"
    [[ "$(grep -c '^secret-file ' "${CASE_DIR}/calls.log")" == "3" ]] || fail "unexpected number of secret files"
}
existing_secret() {  # existing_secret ADMIN BIND CLIENT -> existing-secret.json fixture
    jq -n --arg a "$(printf '%s' "$1" | base64 -w0)" --arg b "$(printf '%s' "$2" | base64 -w0)" --arg c "$(printf '%s' "$3" | base64 -w0)" \
        '{kind: "Secret", data: {ADMIN_PASSWORD: $a, LDAP_BIND_PASSWORD: $b, GITLAB_CLIENT_SECRET: $c}}' > "${CASE_DIR}/existing-secret.json"
}

CREATE_SECRET='^kubectl -n keycloak create secret generic keycloak-realm-secrets --from-file='
CREATE_REALM='^kubectl create -f .*/platform/keycloak/realm-import\.yaml$'
forbid_writes() { forbid_calls "${CREATE_SECRET}"; forbid_calls '^kubectl (create|apply) -f'; forbid_calls '^kubectl .*(delete|patch|replace) '; }

begin_case fresh-configures-everything
state_files
run 0; expect_secret_files; expect_calls "${CREATE_SECRET}"; expect_calls "${CREATE_REALM}"
expect_output "Secret keycloak/keycloak-realm-secrets created"; expect_output "Realm tcn imported."; expect_output "Keycloak is configured."
end_case

begin_case generates-own-values-when-absent
printf '%s' "${BIND}" > "${STATE}/keycloak/svc-keycloak.password"
run 0; expect_output "generated ${STATE}/keycloak/admin.password"; expect_output "generated ${STATE}/keycloak/gitlab-client.secret"
[[ "$(wc -l < "${STATE}/keycloak/admin.password")" == "0" ]] || fail "generated admin.password has a newline"
grep -qxE '[A-Za-z0-9+/]{48}' "${STATE}/keycloak/admin.password" || fail "generated admin.password is not 48 base64 characters"
expect_calls "${CREATE_SECRET}"; [[ "$(grep -c '^secret-file ' "${CASE_DIR}/calls.log")" == "3" ]] || fail "unexpected number of secret files"
end_case

begin_case missing-bind-password-refused
printf '%s' "${ADMIN}" > "${STATE}/keycloak/admin.password"; printf '%s' "${CLIENT}" > "${STATE}/keycloak/gitlab-client.secret"
run 1; forbid_writes; expect_output "svc-keycloak.password is missing"
end_case

begin_case multiline-value-refused
state_files; printf '%s\n' "${BIND}" > "${STATE}/keycloak/svc-keycloak.password"
run 1; forbid_writes; forbid_calls '^secret-file '; expect_output "must be a single line"
end_case

begin_case quote-in-value-refused
state_files; printf 'has-a-"quote"-inside-0123456789' > "${STATE}/keycloak/gitlab-client.secret"
run 1; forbid_writes; forbid_calls '^secret-file '; expect_output "must be a single line"
end_case

begin_case loose-mode-refused
state_files; chmod 0644 "${STATE}/keycloak/svc-keycloak.password"
run 1; forbid_writes; forbid_calls '^secret-file '; expect_output "must be mode 0600"
end_case

begin_case matching-secret-left-unchanged
state_files; existing_secret "${ADMIN}" "${BIND}" "${CLIENT}"
run 0; forbid_calls "${CREATE_SECRET}"; expect_output "left unchanged"; expect_calls "${CREATE_REALM}"
end_case

begin_case mismatching-secret-refused
state_files; existing_secret "${ADMIN}" "other-bind-password-0123456789abcdef" "${CLIENT}"
run 1; forbid_writes; expect_output "does not match the values in"
end_case

begin_case secret-get-error-must-not-write
state_files; : > "${CASE_DIR}/get-error"
run 1; forbid_writes; expect_output "could not read secret keycloak/keycloak-realm-secrets"
end_case

begin_case existing-secret-wrong-shape-refused
state_files; printf '{"kind": "Secret", "data": {"ADMIN_PASSWORD": "eA=="}}' > "${CASE_DIR}/existing-secret.json"
run 1; forbid_writes; expect_output "unexpected shape"
end_case

begin_case realm-dry-run-before-create
state_files
run 0; expect_calls '^kubectl create --dry-run=server --validate=strict -f .*/platform/keycloak/realm-import\.yaml$'; expect_calls "${CREATE_REALM}"
dry_line="$(grep -nE '^kubectl create --dry-run=server' "${CASE_DIR}/calls.log" | head -1 | cut -d: -f1)"
create_line="$(grep -nE "${CREATE_REALM}" "${CASE_DIR}/calls.log" | head -1 | cut -d: -f1)"
if [[ -z "${dry_line}" || -z "${create_line}" ]] || (( dry_line >= create_line )); then fail "the dry-run must come before the create"; fi
end_case

begin_case realm-dry-run-rejected-creates-nothing
state_files; : > "${CASE_DIR}/dry-run-reject"
run 1; forbid_calls "${CREATE_REALM}"; expect_output "rejected the realm import in a strict server-side dry-run"
end_case

begin_case keycloak-not-ready-stops false
state_files
run 1; expect_calls "${CREATE_SECRET}"; forbid_calls '^kubectl create -f'; expect_output "Keycloak is not ready"
end_case

begin_case realm-already-imported-left-unchanged
state_files
printf '{"status":{"conditions":[{"type":"Done","status":"True"},{"type":"HasErrors","status":"False"}]}}' > "${CASE_DIR}/existing-import.json"
run 0; forbid_calls '^kubectl create -f'; expect_output "Realm tcn already imported"
end_case

begin_case realm-import-not-done-refused
state_files
printf '{"status":{"conditions":[{"type":"Started","status":"True"},{"type":"Done","status":"False"},{"type":"HasErrors","status":"True","message":"x"}]}}' > "${CASE_DIR}/existing-import.json"
run 1; forbid_calls '^kubectl create -f'; expect_output "exists but is not Done"
end_case

begin_case realm-import-never-done-times-out true never
state_files
run 1; expect_calls "${CREATE_REALM}"; expect_output "did not finish within 2s"
end_case

begin_case realm-import-errors-stop true errors
state_files
run 1; expect_calls "${CREATE_REALM}"; expect_output "the realm import failed"
end_case

begin_case not-confirmed
state_files
rc=0; env -u CONFIRM_REBUILD STATE_DIR_OVERRIDE="${STATE}" bash "${ROOT_DIR}/scripts/keycloak.sh" > "${CASE_DIR}/out" 2>&1 || rc=$?
[[ "${rc}" == "1" ]] || fail "exit ${rc}, expected 1"; [[ ! -s "${CASE_DIR}/calls.log" ]] || fail "kubectl was called"
end_case

if (( FAILED_CASES > 0 || PASSED != EXPECTED_CASES )); then
    echo "Self-test FAILED: ${PASSED}/${EXPECTED_CASES} cases passed, ${FAILED_CASES} failed." >&2
    exit 1
fi
echo "All ${PASSED} keycloak self-tests passed."
