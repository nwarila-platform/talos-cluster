#!/bin/sh
# Runs every minute inside the hashicorp/vault image (busybox sh): unseals any
# sealed, initialized Vault pod with the threshold keys mounted from the
# vault-unseal Secret. Keys reach Vault on stdin only, never in argv. Every
# Vault request has a short client timeout so one hung pod cannot consume the
# Job's deadline. Exit 1 when a pod stays sealed, is unreachable, returns an
# unreadable status, or is initialized while no keys are mounted; exit 0 only
# when every reachable pod is unsealed or explicitly uninitialized.
set -u

KEY_DIR="${KEY_DIR:-/vault/unseal}"
VAULT_CACERT="${VAULT_CACERT:-/vault/tls/ca.crt}"
VAULT_CLIENT_TIMEOUT="${VAULT_CLIENT_TIMEOUT:-3s}"
export VAULT_CACERT VAULT_CLIENT_TIMEOUT
PODS="${PODS:-vault-0 vault-1 vault-2}"
DOMAIN="${DOMAIN:-vault-internal.vault.svc.cluster.local}"
ADDRS="${ADDRS:-}"

if [ -z "${ADDRS}" ]; then
    for pod in ${PODS}; do
        ADDRS="${ADDRS} https://${pod}.${DOMAIN}:8200"
    done
fi
have_keys=0
if [ -f "${KEY_DIR}/key0" ]; then
    have_keys=1
fi

rc=0
saw_initialized=0
for addr in ${ADDRS}; do
    VAULT_ADDR="${addr}"
    export VAULT_ADDR
    # One status request decides everything about this pod.
    status_json="$(vault status -format=json 2> /dev/null)"
    state=$?
    case "${state}" in
        0)
            saw_initialized=1
            echo "${addr}: unsealed" ;;
        2)
            if printf '%s' "${status_json}" | grep -Eq '"initialized":[[:space:]]*false'; then
                echo "${addr}: not initialized; skipping"
                continue
            fi
            if ! printf '%s' "${status_json}" | grep -Eq '"initialized":[[:space:]]*true'; then
                echo "${addr}: unreadable status"
                rc=1
                continue
            fi
            saw_initialized=1
            if [ "${have_keys}" -eq 0 ]; then
                echo "${addr}: sealed and no unseal keys are mounted at ${KEY_DIR}"
                rc=1
                continue
            fi
            for key in "${KEY_DIR}"/key*; do
                vault write -format=json sys/unseal key=- < "${key}" > /dev/null 2>&1 || true
                if vault status > /dev/null 2>&1; then
                    break
                fi
            done
            if vault status > /dev/null 2>&1; then
                echo "${addr}: unsealed now"
            else
                echo "${addr}: still sealed after submitting the mounted keys"
                rc=1
            fi ;;
        *)
            echo "${addr}: unreachable (vault status exit ${state})"
            rc=1 ;;
    esac
done
if [ "${have_keys}" -eq 0 ] && [ "${saw_initialized}" -eq 1 ]; then
    echo "no unseal keys are mounted at ${KEY_DIR} although Vault is initialized; the vault-unseal Secret is missing"
    rc=1
fi
exit "${rc}"
