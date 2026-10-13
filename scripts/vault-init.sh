#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

if [[ "${CONFIRM_REBUILD:-}" != "TDNHQ-TALCL01" ]]; then
    echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to authorize Vault initialization" >&2
    exit 1
fi

for command in jq kubectl; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done
STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
KUBECONFIG="${STATE_ROOT}/configs/kubeconfig"
export KUBECONFIG
[[ -f "${KUBECONFIG}" ]] || { echo "ERROR: kubeconfig not found: ${KUBECONFIG}" >&2; exit 1; }
actual_server="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
[[ "${actual_server}" == "${CLUSTER_ENDPOINT}" ]] || {
    echo "ERROR: kubeconfig server ${actual_server:-missing} is not ${CLUSTER_ENDPOINT}" >&2
    exit 1
}
INIT_DIR="${STATE_ROOT}/vault"
INIT_FILE="${INIT_DIR}/init.json"
umask 077
mkdir -p "${INIT_DIR}"

for ordinal in 0 1 2; do
    kubectl -n vault wait --for=create "pod/vault-${ordinal}" --timeout=5m
    kubectl -n vault wait --for=jsonpath='{.status.phase}'=Running \
        "pod/vault-${ordinal}" --timeout=5m
done

status_json=""
for _ in $(seq 1 60); do
    status_json="$(kubectl -n vault exec vault-0 -- env \
        VAULT_ADDR=https://127.0.0.1:8200 \
        VAULT_CACERT=/vault/userconfig/tls/ca.crt \
        vault status -format=json 2>/dev/null || true)"
    if jq -e 'has("initialized")' <<<"${status_json:-{}}" >/dev/null 2>&1; then
        break
    fi
    sleep 5
done
jq -e 'has("initialized")' <<<"${status_json:-{}}" >/dev/null || {
    echo "ERROR: vault-0 API did not become available" >&2
    exit 1
}
initialized="$(jq -r '.initialized // false' <<<"${status_json:-{}}")"

if [[ "${initialized}" == "false" ]]; then
    [[ ! -e "${INIT_FILE}" ]] || { echo "ERROR: stale ${INIT_FILE}; inspect before continuing" >&2; exit 1; }
    kubectl -n vault exec vault-0 -- env \
        VAULT_ADDR=https://127.0.0.1:8200 \
        VAULT_CACERT=/vault/userconfig/tls/ca.crt \
        vault operator init -format=json -key-shares=5 -key-threshold=3 \
        > "${INIT_FILE}"
    chmod 0600 "${INIT_FILE}"
elif [[ ! -f "${INIT_FILE}" ]]; then
    echo "ERROR: Vault is initialized but ${INIT_FILE} is absent; use escrowed keys" >&2
    exit 1
fi

jq -e '.unseal_keys_b64 | length == 5' "${INIT_FILE}" >/dev/null
mapfile -t unseal_keys < <(jq -r '.unseal_keys_b64[0:3][]' "${INIT_FILE}")

unseal_pod() {
    local ordinal="$1"
    local key

    for key in "${unseal_keys[@]}"; do
        printf '%s\n' "${key}" | kubectl -n vault exec -i "vault-${ordinal}" -- env \
            VAULT_ADDR=https://127.0.0.1:8200 \
            VAULT_CACERT=/vault/userconfig/tls/ca.crt \
            vault operator unseal >/dev/null
    done
}

# The leader must be available before the retry_join stanzas can attach the
# two followers to the raft cluster.
unseal_pod 0

for ordinal in 1 2; do
    joined=false
    for _ in $(seq 1 60); do
        follower_status="$(kubectl -n vault exec "vault-${ordinal}" -- env \
            VAULT_ADDR=https://127.0.0.1:8200 \
            VAULT_CACERT=/vault/userconfig/tls/ca.crt \
            vault status -format=json 2>/dev/null || true)"
        if [[ "$(jq -r '.initialized // false' <<<"${follower_status:-{}}")" == "true" ]]; then
            joined=true
            break
        fi
        sleep 5
    done
    [[ "${joined}" == "true" ]] || { echo "ERROR: vault-${ordinal} did not join raft" >&2; exit 1; }
    unseal_pod "${ordinal}"
done

for ordinal in 0 1 2; do
    kubectl -n vault wait --for=condition=Ready "pod/vault-${ordinal}" --timeout=5m
done

echo "Vault initialized and unsealed. Immediately escrow ${INIT_FILE} outside this repository."
