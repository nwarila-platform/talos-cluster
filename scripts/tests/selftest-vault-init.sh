#!/usr/bin/env bash
# Stub-based self-test for scripts/vault-init.sh: kubectl is replaced by an
# exported function that models config-view, waits, in-pod status/unseal and
# the vault-unseal Secret, so the fresh path, the rerun path, a mismatching
# existing Secret, a failed Secret read, a malformed Secret, malformed shares
# and secret hygiene are all decidable without a cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"
export CLUSTER_ENDPOINT

for command in jq sha256sum; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT:?}"' EXIT
chmod 0700 "${TEST_ROOT}"

# Five fake 32-byte shares, base64 like Vault's unseal_keys_b64.
SHARES=()
for i in 1 2 3 4 5; do SHARES+=("$(printf 'selftest-share-%d-%s' "$i" "0123456789abcdef0123456789" | head -c 32 | base64 -w0)"); done
make_init_json() {  # make_init_json FILE [share-override-index value]
    jq -n --arg a "${SHARES[0]}" --arg b "${SHARES[1]}" --arg c "${SHARES[2]}" --arg d "${SHARES[3]}" --arg e "${SHARES[4]}" \
        '{unseal_keys_b64: [$a,$b,$c,$d,$e], unseal_keys_hex: [], unseal_shares: 5, unseal_threshold: 3, root_token: "hvs.selftest-root"}' > "$1"
}

kubectl() {
    local -a args=("$@")
    printf 'kubectl %s\n' "$*" >> "${CASE_DIR}/calls.log"
    case "$*" in
        *"config view"*) printf '%s' "${CLUSTER_ENDPOINT}" ;;
        *"vault status -format=json"*)
            printf '{"initialized": %s, "sealed": %s}' "${STUB_INITIALIZED}" "${STUB_SEALED}" ;;
        *"sys/unseal key=-"*)
            cat > "${CASE_DIR}/stdin-$(date +%s%N)"
            printf '{"sealed": false}' ;;
        *"get secret vault-unseal --ignore-not-found -o json"*)
            if [[ -f "${CASE_DIR}/get-error" ]]; then
                echo 'Error from server (ServiceUnavailable): the server is currently unable to handle the request' >&2; return 1
            elif [[ -f "${CASE_DIR}/existing-secret.json" ]]; then cat "${CASE_DIR}/existing-secret.json"; fi ;;
        *"create secret generic vault-unseal --from-file="*)
            local dir="${args[6]#--from-file=}" f
            for f in "${dir}"/*; do printf 'secret-file %s sha256=%s\n' "${f##*/}" "$(sha256sum "${f}" | cut -c1-64)" >> "${CASE_DIR}/calls.log"; done
            printf 'secret/vault-unseal created\n' ;;
        *"apply -f -"*) cat > "${CASE_DIR}/applied.yaml"; printf 'secret/vault-unseal configured\n' ;;
    esac
    return 0
}
export -f kubectl
[[ "$(bash -c 'type -t kubectl')" == "function" ]] || { echo "ERROR: stub export failed" >&2; exit 1; }

PASSED=0; FAILED_CASES=0; CASE_OK=1
EXPECTED_CASES="$(grep -c '^begin_case ' "${BASH_SOURCE[0]}")"
begin_case() {
    CASE_NAME="$1"; CASE_DIR="${TEST_ROOT}/${CASE_NAME}"; STATE="${CASE_DIR}/state"; CASE_OK=1
    export CASE_DIR STUB_INITIALIZED="${2:-true}" STUB_SEALED="${3:-false}"
    mkdir -p "${STATE}/configs" "${STATE}/vault"; printf 'stub kubeconfig\n' > "${STATE}/configs/kubeconfig"
    : > "${CASE_DIR}/calls.log"; : > "${CASE_DIR}/out"
}
fail() { echo "FAIL ${CASE_NAME}: $1" >&2; CASE_OK=0; }
end_case() { if (( CASE_OK )); then echo "PASS ${CASE_NAME}"; PASSED=$((PASSED + 1)); else FAILED_CASES=$((FAILED_CASES + 1)); fi; }
run() {  # run EXPECTED_EXIT
    local rc=0
    env -u KUBECONFIG -u VAULT_ADDR STATE_DIR_OVERRIDE="${STATE}" CONFIRM_REBUILD=TDNHQ-TALCL01 \
        bash "${ROOT_DIR}/scripts/vault-init.sh" > "${CASE_DIR}/out" 2>&1 || rc=$?
    [[ "${rc}" == "$1" ]] || fail "exit ${rc}, expected $1: $(tail -n 3 "${CASE_DIR}/out" | tr '\n' ' ')"
    local share
    for share in "${SHARES[@]}"; do
        ! grep -qF -- "${share}" "${CASE_DIR}/out" || fail "a share leaked to output"
        ! grep -qF -- "${share}" "${CASE_DIR}/calls.log" || fail "a share appeared in argv"
    done
}
expect_calls() { grep -qE -- "$1" "${CASE_DIR}/calls.log" || fail "missing call matching: $1"; }
forbid_calls() { ! grep -qE -- "$1" "${CASE_DIR}/calls.log" || fail "forbidden call matching: $1"; }
expect_output() { grep -qF -- "$1" "${CASE_DIR}/out" || fail "output lacks: $1"; }
expect_secret_files() {  # the Secret was built from exactly shares 0..2
    local i
    for i in 0 1 2; do
        expect_calls "^secret-file key${i} sha256=$(printf '%s' "${SHARES[$i]}" | sha256sum | cut -c1-64)$"
    done
    [[ "$(grep -c '^secret-file ' "${CASE_DIR}/calls.log")" == "3" ]] || fail "unexpected number of secret files"
}
existing_secret() {  # existing_secret SHARE0 SHARE1 SHARE2 -> existing-secret.json fixture
    jq -n --arg a "$(printf '%s' "$1" | base64 -w0)" --arg b "$(printf '%s' "$2" | base64 -w0)" --arg c "$(printf '%s' "$3" | base64 -w0)" \
        '{kind: "Secret", data: {key0: $a, key1: $b, key2: $c}}' > "${CASE_DIR}/existing-secret.json"
}

CREATE='^kubectl -n vault create secret generic vault-unseal --from-file='
forbid_writes() { forbid_calls "${CREATE}"; forbid_calls '^kubectl apply -f -$'; forbid_calls '^kubectl .*(delete|patch|replace) '; }

begin_case rerun-creates-secret true false
make_init_json "${STATE}/vault/init.json"
run 0; expect_secret_files; expect_calls "${CREATE}"; forbid_calls '^kubectl apply -f -$'; expect_output "stored in secret vault/vault-unseal"
expect_calls 'vault write -format=json sys/unseal key=-'
end_case

begin_case rerun-matching-secret-is-idempotent true false
make_init_json "${STATE}/vault/init.json"; existing_secret "${SHARES[0]}" "${SHARES[1]}" "${SHARES[2]}"
run 0; forbid_writes; expect_output "left unchanged"
end_case

begin_case rerun-mismatching-secret-refused true false
make_init_json "${STATE}/vault/init.json"; existing_secret "${SHARES[0]}" "${SHARES[1]}" "${SHARES[4]}"
run 1; forbid_writes; expect_output "does not match the shares in"
end_case

begin_case secret-get-error-must-not-write true false
make_init_json "${STATE}/vault/init.json"; : > "${CASE_DIR}/get-error"
run 1; forbid_writes; expect_output "could not read secret vault/vault-unseal"
end_case

begin_case existing-secret-wrong-shape-refused true false
make_init_json "${STATE}/vault/init.json"; printf '{"kind": "Secret"}' > "${CASE_DIR}/existing-secret.json"
run 1; forbid_writes; expect_output "unexpected shape"
end_case

begin_case malformed-share-refused true false
make_init_json "${STATE}/vault/init.json"
jq '.unseal_keys_b64[1] = "short"' "${STATE}/vault/init.json" > "${STATE}/vault/init.tmp" && mv "${STATE}/vault/init.tmp" "${STATE}/vault/init.json"
run 1; forbid_writes; forbid_calls '^secret-file '; expect_output "is not a base64 unseal share"
end_case

begin_case initialized-without-init-file-refused true false
run 1; expect_output "use escrowed keys"; forbid_calls 'sys/unseal'
end_case

begin_case not-confirmed
make_init_json "${STATE}/vault/init.json"
rc=0; env -u CONFIRM_REBUILD STATE_DIR_OVERRIDE="${STATE}" bash "${ROOT_DIR}/scripts/vault-init.sh" > "${CASE_DIR}/out" 2>&1 || rc=$?
[[ "${rc}" == "1" ]] || fail "exit ${rc}, expected 1"; [[ ! -s "${CASE_DIR}/calls.log" ]] || fail "kubectl was called"
end_case

if (( FAILED_CASES > 0 || PASSED != EXPECTED_CASES )); then
    echo "Self-test FAILED: ${PASSED}/${EXPECTED_CASES} cases passed, ${FAILED_CASES} failed." >&2
    exit 1
fi
echo "All ${PASSED} vault-init self-tests passed."
