#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

if [[ "${CONFIRM_REBUILD:-}" != "TDNHQ-TALCL01" ]]; then
    echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to authorize Vault TLS changes" >&2
    exit 1
fi

for command in openssl kubectl; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
TLS_DIR="${STATE_ROOT}/vault/tls"
require_cert_match() {  # require_cert_match -checkhost|-checkip <value>
    local result
    result="$(openssl x509 "$1" "$2" -noout -in "${TLS_DIR}/tls.crt" 2>&1 || true)"
    [[ "${result}" == *" does match certificate"* ]] || {
        echo "ERROR: Vault server certificate does not cover $2: ${result}" >&2
        exit 1
    }
}
KUBECONFIG="${STATE_ROOT}/configs/kubeconfig"
export KUBECONFIG
[[ -f "${KUBECONFIG}" ]] || { echo "ERROR: kubeconfig not found: ${KUBECONFIG}" >&2; exit 1; }
actual_server="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
[[ "${actual_server}" == "${CLUSTER_ENDPOINT}" ]] || {
    echo "ERROR: kubeconfig server ${actual_server:-missing} is not ${CLUSTER_ENDPOINT}" >&2
    exit 1
}
umask 077
mkdir -p "${TLS_DIR}"
vault_sans="DNS:vault,DNS:vault.vault,DNS:vault.vault.svc,DNS:vault.vault.svc.cluster.local,DNS:vault-internal,DNS:*.vault-internal,DNS:*.vault-internal.vault.svc,DNS:*.vault-internal.vault.svc.cluster.local,DNS:localhost"
for entry in ${CP_NODES}; do
    vault_sans+=",IP:${entry##*:}"
done
vault_sans+=",IP:127.0.0.1"

if [[ -e "${TLS_DIR}/ca.key" || -e "${TLS_DIR}/ca.crt" ]]; then
    [[ -f "${TLS_DIR}/ca.key" && -f "${TLS_DIR}/ca.crt" ]] || {
        echo "ERROR: partial Vault CA state in ${TLS_DIR}; inspect before replacing it" >&2
        exit 1
    }
else
    openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 3650 \
        -subj "/CN=TDNHQ-TALCL01 Vault CA" \
        -keyout "${TLS_DIR}/ca.key" -out "${TLS_DIR}/ca.crt"
fi

if [[ -e "${TLS_DIR}/tls.key" || -e "${TLS_DIR}/tls.crt" ]]; then
    [[ -f "${TLS_DIR}/tls.key" && -f "${TLS_DIR}/tls.crt" ]] || {
        echo "ERROR: partial Vault server TLS state in ${TLS_DIR}; inspect before replacing it" >&2
        exit 1
    }
    localhost_check="$(openssl x509 -checkhost localhost -noout -in "${TLS_DIR}/tls.crt" 2>/dev/null || true)"
    loopback_check="$(openssl x509 -checkip 127.0.0.1 -noout -in "${TLS_DIR}/tls.crt" 2>/dev/null || true)"
    if [[ "${localhost_check}" != *" does match certificate"* \
        || "${loopback_check}" != *" does match certificate"* ]]; then
        echo "ERROR: existing Vault server certificate lacks loopback SANs; move ${TLS_DIR}/tls.{crt,key,csr} aside to re-issue" >&2
        exit 1
    fi
else
    openssl req -newkey rsa:3072 -sha256 -nodes \
        -subj "/CN=vault.vault.svc.cluster.local" \
        -keyout "${TLS_DIR}/tls.key" -out "${TLS_DIR}/tls.csr"
    openssl x509 -req -sha256 -days 825 \
        -in "${TLS_DIR}/tls.csr" \
        -CA "${TLS_DIR}/ca.crt" -CAkey "${TLS_DIR}/ca.key" -CAcreateserial \
        -out "${TLS_DIR}/tls.crt" \
        -extfile <(printf '%s\n' \
            "subjectAltName=${vault_sans}" \
            'extendedKeyUsage=serverAuth,clientAuth')
fi

ca_key_id="$(openssl pkey -in "${TLS_DIR}/ca.key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
ca_cert_id="$(openssl x509 -in "${TLS_DIR}/ca.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
tls_key_id="$(openssl pkey -in "${TLS_DIR}/tls.key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
tls_cert_id="$(openssl x509 -in "${TLS_DIR}/tls.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
[[ "${ca_key_id}" == "${ca_cert_id}" ]] || { echo "ERROR: Vault CA key and certificate do not match" >&2; exit 1; }
[[ "${tls_key_id}" == "${tls_cert_id}" ]] || { echo "ERROR: Vault TLS key and certificate do not match" >&2; exit 1; }
openssl verify -CAfile "${TLS_DIR}/ca.crt" "${TLS_DIR}/ca.crt" >/dev/null
openssl verify -purpose sslserver -CAfile "${TLS_DIR}/ca.crt" "${TLS_DIR}/tls.crt" >/dev/null
openssl x509 -checkend 86400 -noout -in "${TLS_DIR}/ca.crt" >/dev/null
openssl x509 -checkend 86400 -noout -in "${TLS_DIR}/tls.crt" >/dev/null
for hostname in vault vault.vault vault.vault.svc vault.vault.svc.cluster.local \
    vault-0.vault-internal.vault.svc.cluster.local \
    vault-1.vault-internal.vault.svc.cluster.local \
    vault-2.vault-internal.vault.svc.cluster.local \
    localhost; do
    require_cert_match -checkhost "${hostname}"
done
for entry in ${CP_NODES}; do
    require_cert_match -checkip "${entry##*:}"
done
require_cert_match -checkip 127.0.0.1

kubectl create namespace vault --dry-run=client -o yaml | kubectl apply -f -
kubectl -n vault create secret generic vault-server-tls \
    --from-file=ca.crt="${TLS_DIR}/ca.crt" \
    --from-file=tls.crt="${TLS_DIR}/tls.crt" \
    --from-file=tls.key="${TLS_DIR}/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "Vault CA: ${TLS_DIR}/ca.crt"
