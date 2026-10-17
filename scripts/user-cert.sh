#!/usr/bin/env bash
# A person's client certificate from the Vault PKI (role tcn-user), for signing in to Keycloak with a
# certificate in the browser: make user-cert NAME=<AD account name>. The RSA 3072 key is generated
# here; Vault signs it with CN and UPN <user>@tcn.trinitytechnicalservices.com (one year). Output in
# .state/users/: <user>.p12 (key, certificate, issuing CA and root, for the browser), <user>.p12.pass
# (its random password) and tcn-root-ca.crt (the root the browser must trust for Keycloak on the LAN).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"
user="${USER_NAME:-}"
[[ "${user}" =~ ^[a-z0-9][a-z0-9._-]{0,19}$ ]] || { echo "ERROR: set NAME=<AD account name> (lower case, as in AD)" >&2; exit 1; }
upn="${user}@tcn.trinitytechnicalservices.com"
STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
OUT="${STATE_ROOT}/users"
VADDR="https://${CP_NODES%% *}"; VADDR="https://${VADDR##*:}:30200"
umask 077
mkdir -p "${OUT}"
W="$(mktemp -d)"; trap 'rm -rf "${W}"' EXIT

KUBECONFIG="${STATE_ROOT}/configs/kubeconfig" kubectl -n keycloak get configmap root-ca -o jsonpath='{.data.ca\.crt}' > "${OUT}/tcn-root-ca.crt"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${W}/user.key" 2>/dev/null
openssl req -new -key "${W}/user.key" -subj "/CN=${upn}" -out "${W}/user.csr"
jq -n --rawfile csr "${W}/user.csr" --arg cn "${upn}" \
    '{csr: $csr, common_name: $cn, other_sans: ("1.3.6.1.4.1.311.20.2.3;UTF8:" + $cn), use_csr_common_name: false, use_csr_sans: false, ttl: "8760h", format: "pem"}' > "${W}/req.json"
printf 'header = "X-Vault-Token: %s"\nheader = "Content-Type: application/json"\ndata = "@%s"\n' \
    "$(jq -r .root_token "${STATE_ROOT}/vault/init.json")" "${W}/req.json" \
    | env -i PATH="${PATH}" HOME="${HOME}" curl --disable -sS -f --max-time 30 --cacert "${STATE_ROOT}/vault/tls/ca.crt" -K - \
        "${VADDR}/v1/pki-int-linux/sign/tcn-user" > "${W}/out.json"
jq -r .data.certificate "${W}/out.json" > "${W}/user.crt"
jq -r .data.issuing_ca "${W}/out.json" > "${W}/issuing.crt"
openssl verify -CAfile "${OUT}/tcn-root-ca.crt" -untrusted "${W}/issuing.crt" "${W}/user.crt" > /dev/null \
    || { echo "ERROR: the signed certificate does not chain to the PKI root" >&2; exit 1; }
openssl x509 -in "${W}/user.crt" -noout -ext extendedKeyUsage | grep -q 'TLS Web Client Authentication' \
    || { echo "ERROR: the certificate lacks client authentication" >&2; exit 1; }

openssl rand -base64 24 | tr -d '\n' > "${OUT}/${user}.p12.pass"
cat "${W}/issuing.crt" "${OUT}/tcn-root-ca.crt" > "${W}/chain.crt"
openssl pkcs12 -export -inkey "${W}/user.key" -in "${W}/user.crt" -certfile "${W}/chain.crt" \
    -name "${upn} (Trinity Technical Services)" -passout "file:${OUT}/${user}.p12.pass" -out "${OUT}/${user}.p12"
echo "Issued $(openssl x509 -in "${W}/user.crt" -noout -subject -enddate | tr '\n' ' ')"
echo "Browser bundle: ${OUT}/${user}.p12 (password in ${OUT}/${user}.p12.pass); trust ${OUT}/tcn-root-ca.crt as a root."
