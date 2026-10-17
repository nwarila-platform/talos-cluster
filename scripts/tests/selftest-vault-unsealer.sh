#!/usr/bin/env bash
# Live self-test for platform/vault/unsealer.sh against two throwaway Vault
# servers on localhost: a dev server (initialized, started with
# -dev-no-store-token and a private HOME) and a plain in-memory server that
# starts uninitialized. A logging wrapper in front of the real vault binary
# counts unseal submissions so the per-key stop is observable. Every
# invocation's output is scanned for key material before it is discarded.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
UNSEALER="${ROOT_DIR}/platform/vault/unsealer.sh"

for command in vault openssl; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

TEST_ROOT="$(mktemp -d)"
# /tmp may be mounted noexec, so the vault wrapper lives under the caller's
# cache directory (SELFTEST_BIN_PARENT overrides) and is proven to work below.
BIN_PARENT="${SELFTEST_BIN_PARENT:-${XDG_CACHE_HOME:-${HOME}/.cache}}"
mkdir -p "${BIN_PARENT}"
BIN_DIR="$(mktemp -d "${BIN_PARENT}/talos-selftest.XXXXXX")"
DEV_PID=""
RAW_PID=""
cleanup() {
    for pid in "${DEV_PID}" "${RAW_PID}"; do
        [[ -z "${pid}" ]] || { kill "${pid}" 2>/dev/null || true; wait "${pid}" 2>/dev/null || true; }
    done
    rm -rf "${TEST_ROOT:?}" "${BIN_DIR:?}"
}
trap cleanup EXIT INT TERM
chmod 0700 "${TEST_ROOT}"
PORT="${SELFTEST_VAULT_PORT:-18260}"
[[ "${PORT}" =~ ^[0-9]{4,5}$ ]] || { echo "ERROR: SELFTEST_VAULT_PORT must be a port number" >&2; exit 1; }
RAW_PORT=$(( PORT + 1 ))
DEV_ADDR="http://127.0.0.1:${PORT}"
RAW_ADDR="http://127.0.0.1:${RAW_PORT}"
export HOME="${TEST_ROOT}/home"
mkdir -p "${HOME}"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "${TEST_ROOT}/dummy.key" -out "${TEST_ROOT}/dummy.crt" -subj /CN=selftest -days 1 > /dev/null 2>&1

# Dev server: initialized and unsealed.
VAULT_ADDR="${DEV_ADDR}" vault server -dev -dev-no-store-token -dev-listen-address="127.0.0.1:${PORT}" \
    -dev-root-token-id=selftest-root > "${TEST_ROOT}/dev.log" 2>&1 &
DEV_PID=$!
# Raw server: in-memory storage, starts uninitialized.
cat > "${TEST_ROOT}/raw.hcl" <<EOF
storage "inmem" {}
listener "tcp" {
  address     = "127.0.0.1:${RAW_PORT}"
  tls_disable = true
}
disable_mlock = true
EOF
vault server -config="${TEST_ROOT}/raw.hcl" > "${TEST_ROOT}/raw.log" 2>&1 &
RAW_PID=$!
# The dev server answers status before it prints its unseal key, so wait for both.
for _ in $(seq 1 60); do
    VAULT_ADDR="${DEV_ADDR}" vault status > /dev/null 2>&1 && grep -q 'Unseal Key: ' "${TEST_ROOT}/dev.log" && break
    sleep 0.5
done
VAULT_ADDR="${DEV_ADDR}" vault status > /dev/null 2>&1 || {
    echo "ERROR: dev server did not start: $(grep -iE 'error|address' "${TEST_ROOT}/dev.log" | head -n 1)" >&2; exit 1; }
raw_state=1
for _ in $(seq 1 60); do
    raw_state=0
    VAULT_ADDR="${RAW_ADDR}" vault status > /dev/null 2>&1 || raw_state=$?
    [[ "${raw_state}" -eq 2 ]] && break
    sleep 0.5
done
[[ "${raw_state}" -eq 2 ]] || {
    echo "ERROR: raw server did not start uninitialized: $(grep -iE 'error|address' "${TEST_ROOT}/raw.log" | head -n 1)" >&2; exit 1; }
dev_key="$(grep -o 'Unseal Key: .*' "${TEST_ROOT}/dev.log" | awk '{print $3}' || true)"
[[ -n "${dev_key}" ]] || { echo "ERROR: dev server printed no unseal key" >&2; exit 1; }

# Logging wrapper in front of the real vault binary, proven to be in effect.
REAL_VAULT="$(command -v vault)"
cat > "${BIN_DIR}/vault" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "${TEST_ROOT}/vault-calls.log"
exec "${REAL_VAULT}" "\$@"
EOF
chmod 0755 "${BIN_DIR}/vault"
: > "${TEST_ROOT}/vault-calls.log"
env -i PATH="${BIN_DIR}:${PATH}" HOME="${TEST_ROOT}/home" sh -c 'vault version' > /dev/null 2>&1 || true
grep -qx 'version' "${TEST_ROOT}/vault-calls.log" || {
    echo "ERROR: the vault wrapper in ${BIN_DIR} is not executable (noexec mount?); set SELFTEST_BIN_PARENT" >&2; exit 1; }

PASSED=0
FAILED_CASES=0
EXPECTED_CASES="$(grep -c '^begin_case ' "${BASH_SOURCE[0]}")"
CASE_OK=1
begin_case() { CASE_NAME="$1"; CASE_OK=1; : > "${TEST_ROOT}/vault-calls.log"; }
fail() { echo "FAIL ${CASE_NAME}: $1" >&2; CASE_OK=0; }
end_case() { if (( CASE_OK )); then echo "PASS ${CASE_NAME}"; PASSED=$((PASSED + 1)); else FAILED_CASES=$((FAILED_CASES + 1)); fi; }
expect_output() { grep -qF -- "$1" "${TEST_ROOT}/out" || fail "output lacks: $1"; }
expect_rc() { [[ "$2" == "$1" ]] || fail "exit $2, expected $1: $(tr '\n' ' ' < "${TEST_ROOT}/out")"; }
unseal_calls() { grep -c 'sys/unseal' "${TEST_ROOT}/vault-calls.log" || true; }
keys_good="${TEST_ROOT}/keys-good"; mkdir -p "${keys_good}"; printf '%s' "${dev_key}" > "${keys_good}/key0"
keys_bad="${TEST_ROOT}/keys-bad"; mkdir -p "${keys_bad}"
printf '%s' "${dev_key}" | tr 'A-Za-z' 'N-ZA-Mn-za-m' > "${keys_bad}/key0"
printf '%s' "${dev_key}" > "${keys_bad}/key1"   # the correct key comes second
printf '%s' "${dev_key}" | tr 'A-Za-z' 'N-ZA-Mn-za-m' > "${keys_bad}/key2"   # must never be submitted
keys_none="${TEST_ROOT}/keys-none"; mkdir -p "${keys_none}"
# run_unsealer KEY_DIR ADDRS: prints the script's exit; every invocation's output
# is scanned for the real and the altered key before anything else happens.
run_unsealer() {
    local rc=0
    env -i PATH="${BIN_DIR}:${PATH}" HOME="${TEST_ROOT}/home" KEY_DIR="$1" ADDRS="$2" \
        VAULT_CACERT="${TEST_ROOT}/dummy.crt" sh "${UNSEALER}" > "${TEST_ROOT}/out" 2>&1 || rc=$?
    ! grep -qF -- "${dev_key}" "${TEST_ROOT}/out" || fail "unseal key leaked to output"
    ! grep -qF -- "$(cat "${keys_bad}/key0")" "${TEST_ROOT}/out" || fail "altered key leaked to output"
    ! grep -qF -- "${dev_key}" "${TEST_ROOT}/vault-calls.log" || fail "unseal key appeared in argv"
    printf '%s' "${rc}"
}
dev_sealed() { VAULT_ADDR="${DEV_ADDR}" VAULT_TOKEN=selftest-root vault operator seal > /dev/null; }
dev_is_unsealed() { VAULT_ADDR="${DEV_ADDR}" vault status > /dev/null 2>&1; }

begin_case keys-on-stdin-only
grep -qE 'key=\$|key="\$|operator unseal' "${UNSEALER}" && fail "argv key usage found"
grep -q 'key=- <' "${UNSEALER}" || fail "stdin key submission not found"
end_case

begin_case unsealed-noop
expect_rc 0 "$(run_unsealer "${keys_good}" "${DEV_ADDR}")"
expect_output "${DEV_ADDR}: unsealed"
[[ "$(unseal_calls)" == "0" ]] || fail "unseal submitted to an unsealed vault"
end_case

begin_case sealed-unsealed
dev_sealed
expect_rc 0 "$(run_unsealer "${keys_good}" "${DEV_ADDR}")"
expect_output "${DEV_ADDR}: unsealed now"
dev_is_unsealed || fail "vault still sealed"
[[ "$(unseal_calls)" == "1" ]] || fail "expected exactly one unseal submission, got $(unseal_calls)"
end_case

begin_case stops-after-threshold
dev_sealed
expect_rc 0 "$(run_unsealer "${keys_bad}" "${DEV_ADDR}")"
expect_output "${DEV_ADDR}: unsealed now"
[[ "$(unseal_calls)" == "2" ]] || fail "expected two submissions (bad then good), got $(unseal_calls)"
end_case

begin_case wrong-key-fails
dev_sealed
mkdir -p "${TEST_ROOT}/keys-only-bad"; cp "${keys_bad}/key0" "${TEST_ROOT}/keys-only-bad/key0"
expect_rc 1 "$(run_unsealer "${TEST_ROOT}/keys-only-bad" "${DEV_ADDR}")"
expect_output "still sealed"
! dev_is_unsealed || fail "vault became unsealed with a wrong key"
run_unsealer "${keys_good}" "${DEV_ADDR}" > /dev/null
dev_is_unsealed || fail "could not restore the dev server"
end_case

begin_case no-keys-unsealed-initialized-fails
expect_rc 1 "$(run_unsealer "${keys_none}" "${DEV_ADDR}")"
expect_output "vault-unseal Secret is missing"
[[ "$(unseal_calls)" == "0" ]] || fail "unseal attempted without keys"
end_case

begin_case no-keys-sealed-initialized-fails
dev_sealed
expect_rc 1 "$(run_unsealer "${keys_none}" "${DEV_ADDR}")"
expect_output "sealed and no unseal keys are mounted"
! dev_is_unsealed || fail "vault became unsealed without keys"
run_unsealer "${keys_good}" "${DEV_ADDR}" > /dev/null
end_case

begin_case uninitialized-skipped
expect_rc 0 "$(run_unsealer "${keys_none}" "${RAW_ADDR}")"
expect_output "${RAW_ADDR}: not initialized; skipping"
[[ "$(unseal_calls)" == "0" ]] || fail "unseal attempted on an uninitialized vault"
end_case

begin_case unreachable-fails
expect_rc 1 "$(run_unsealer "${keys_good}" "http://127.0.0.1:1 ${DEV_ADDR}")"
expect_output "http://127.0.0.1:1: unreachable"
expect_output "${DEV_ADDR}: unsealed"
end_case

begin_case initialized-raw-server-unsealed
VAULT_ADDR="${RAW_ADDR}" vault operator init -format=json -key-shares=1 -key-threshold=1 > "${TEST_ROOT}/raw-init.json"
raw_key="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["unseal_keys_b64"][0])' "${TEST_ROOT}/raw-init.json")"
mkdir -p "${TEST_ROOT}/keys-raw"; printf '%s' "${raw_key}" > "${TEST_ROOT}/keys-raw/key0"
expect_rc 0 "$(run_unsealer "${TEST_ROOT}/keys-raw" "${RAW_ADDR}")"
expect_output "${RAW_ADDR}: unsealed now"
VAULT_ADDR="${RAW_ADDR}" vault status > /dev/null 2>&1 || fail "raw server still sealed"
! grep -qF -- "${raw_key}" "${TEST_ROOT}/out" || fail "raw key leaked"
end_case

begin_case no-side-effects-outside-test-root
[[ ! -e "${HOME}/.vault-token" ]] || fail "a server stored a token in HOME"
end_case

if (( FAILED_CASES > 0 || PASSED != EXPECTED_CASES )); then
    echo "Self-test FAILED: ${PASSED}/${EXPECTED_CASES} cases passed, ${FAILED_CASES} failed." >&2
    exit 1
fi
echo "All ${PASSED} Vault unsealer self-tests passed."
