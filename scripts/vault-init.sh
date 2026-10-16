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

EMPTY_JSON='{}'
status_json=""
for _ in $(seq 1 60); do
    status_json="$(kubectl -n vault exec vault-0 -- env \
        VAULT_ADDR=https://127.0.0.1:8200 \
        VAULT_CACERT=/vault/userconfig/tls/ca.crt \
        vault status -format=json 2>/dev/null || true)"
    if jq -e 'has("initialized")' <<<"${status_json:-${EMPTY_JSON}}" >/dev/null 2>&1; then
        break
    fi
    sleep 5
done
jq -e 'has("initialized")' <<<"${status_json:-${EMPTY_JSON}}" >/dev/null || {
    echo "ERROR: vault-0 API did not become available" >&2
    exit 1
}
initialized="$(jq -r '.initialized // false' <<<"${status_json:-${EMPTY_JSON}}")"

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
            vault write -format=json sys/unseal key=- >/dev/null
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
        if [[ "$(jq -r '.initialized // false' <<<"${follower_status:-${EMPTY_JSON}}")" == "true" ]]; then
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

# Threshold keys for the in-cluster unsealer (platform/vault/unsealer.yaml): a
# pod that restarts sealed is unsealed without a human. Shares are validated as
# base64 before they leave the file. The existing Secret is read fail-closed
# (only a successful read decides; an absent Secret is an empty successful
# answer), a Secret holding different shares is never touched, and a missing
# Secret is created with `kubectl create`, which refuses to overwrite one that
# appeared in between.
# The shares live in their own directory (nothing else may land next to them:
# the Secret is built from every file in it); scratch output goes beside it.
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir:?}"' EXIT
key_dir="${work_dir}/keys"
mkdir -m 0700 "${key_dir}"
for index in 0 1 2; do
    jq -er --argjson i "${index}" \
        '.unseal_keys_b64[$i] | select(type == "string" and test("^[A-Za-z0-9+/]{40,}={0,2}$"))' \
        "${INIT_FILE}" 2>/dev/null | tr -d '\n' > "${key_dir}/key${index}" || {
        echo "ERROR: unseal_keys_b64[${index}] in ${INIT_FILE} is not a base64 unseal share" >&2
        exit 1
    }
done
if ! existing="$(kubectl -n vault get secret vault-unseal --ignore-not-found -o json 2> "${work_dir}/get.err")"; then
    echo "ERROR: could not read secret vault/vault-unseal (not deciding presence): $(tr '\n' ' ' < "${work_dir}/get.err")" >&2
    exit 1
fi
if [[ -n "${existing}" ]]; then
    jq -e '.kind == "Secret" and (.data | type) == "object"' <<<"${existing}" >/dev/null 2>&1 || {
        echo "ERROR: secret vault/vault-unseal has an unexpected shape; inspect it before continuing" >&2
        exit 1
    }
    for index in 0 1 2; do
        expected="$(base64 -w0 < "${key_dir}/key${index}")"
        actual="$(jq -r --arg k "key${index}" '.data[$k] // ""' <<<"${existing}")"
        [[ "${actual}" == "${expected}" ]] || {
            echo "ERROR: secret vault/vault-unseal holds key${index} that does not match the shares in" \
                "${INIT_FILE}; refusing to overwrite it (delete the secret deliberately if it is stale)" >&2
            exit 1
        }
    done
    echo "Secret vault/vault-unseal already holds shares 0-2 from ${INIT_FILE}; left unchanged."
else
    kubectl -n vault create secret generic vault-unseal --from-file="${key_dir}"
    echo "Unseal keys 0-2 stored in secret vault/vault-unseal for the in-cluster unsealer."
fi

echo "Vault initialized and unsealed. Immediately escrow ${INIT_FILE} outside this repository."
