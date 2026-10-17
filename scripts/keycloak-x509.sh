#!/usr/bin/env bash
# Certificate sign-in for the tcn realm (run by make keycloak after the realm import; rerunnable).
# The realm's browser flow becomes browser-x509: a copy of Keycloak's built-in browser flow with the
# X509/Validate Username Form step right after the cookie check. A browser that presents a client
# certificate from the Vault PKI (make user-cert) gets a "continue as <user>" page; one without a
# certificate gets the usual password form. The username is the CN's part before
# @tcn.trinitytechnicalservices.com, looked up as username or email (so through the AD federation),
# and only certificates with clientAuth count. Keycloak itself asks for and verifies certificates
# (https-client-auth=request against the PKI, platform/keycloak/keycloak.yaml), which happens only
# where TLS ends at Keycloak: on the LAN. The flow is set through the admin API because a realm
# import that declares one flow must declare every built-in flow too.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"
STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
export KUBECONFIG="${STATE_ROOT}/configs/kubeconfig"
KC=https://keycloak.trinitytechnicalservices.com
W="$(mktemp -d)"; trap 'rm -rf "${W}"' EXIT
kubectl -n keycloak get configmap root-ca -o jsonpath='{.data.ca\.crt}' > "${W}/root.crt"

# Keycloak over the LAN path (the VIP), its certificate checked against the PKI root; credentials and
# tokens reach curl only through its configuration on stdin.
kcurl() { env -i PATH="${PATH}" HOME="${HOME}" curl --disable -sS --max-time 30 --cacert "${W}/root.crt" \
    --resolve "keycloak.trinitytechnicalservices.com:443:${CLUSTER_VIP}" -K - "$@"; }
admin_user="$(kubectl -n keycloak get secret keycloak-initial-admin -o jsonpath='{.data.username}' | base64 -d)"
TOKEN="$({ printf 'data-urlencode = "grant_type=password"\ndata-urlencode = "client_id=admin-cli"\ndata-urlencode = "username=%s"\n' "${admin_user}"
           printf 'data-urlencode = "password=%s"\n' "$(kubectl -n keycloak get secret keycloak-initial-admin -o jsonpath='{.data.password}' | base64 -d)"; } \
         | kcurl "${KC}/realms/master/protocol/openid-connect/token" | jq -r .access_token)"
[[ -n "${TOKEN}" && "${TOKEN}" != null ]] || { echo "ERROR: no admin token from Keycloak" >&2; exit 1; }
# api METHOD PATH [JSON-FILE]: prints the body; fails on an HTTP error.
api() {
    { printf 'header = "Authorization: Bearer %s"\nrequest = %s\n' "${TOKEN}" "$1"
      [[ -z "${3:-}" ]] || printf 'header = "Content-Type: application/json"\ndata = "@%s"\n' "$3"; } \
        | kcurl -f "${KC}/admin/realms/tcn$2"
}
flows=/authentication/flows
executions() { api GET "${flows}/browser-x509/executions"; }

if ! api GET "${flows}" | jq -e '.[] | select(.alias == "browser-x509")' > /dev/null; then
    echo '{"newName":"browser-x509"}' > "${W}/copy.json"
    api POST "${flows}/browser/copy" "${W}/copy.json" > /dev/null
    echo '{"provider":"auth-x509-client-username-form"}' > "${W}/step.json"
    api POST "${flows}/browser-x509/executions/execution" "${W}/step.json" > /dev/null
    echo "Created flow browser-x509."
fi
step="$(executions | jq -r '.[] | select(.providerId == "auth-x509-client-username-form") | .id')"
[[ -n "${step}" ]] || { echo "ERROR: browser-x509 has no certificate step" >&2; exit 1; }
# Directly after the cookie check, before the password forms.
for _ in 1 2 3 4 5 6; do
    [[ "$(executions | jq -r --arg s "${step}" '[.[] | select(.level == 0) | .id] | index($s)')" -le 1 ]] && break
    api POST "/authentication/executions/${step}/raise-priority" > /dev/null
done
executions | jq --arg s "${step}" '.[] | select(.id == $s) | .requirement = "ALTERNATIVE"' > "${W}/requirement.json"
api PUT "${flows}/browser-x509/executions" "${W}/requirement.json" > /dev/null
if [[ -z "$(executions | jq -r --arg s "${step}" '.[] | select(.id == $s) | .authenticationConfig // empty')" ]]; then
    jq -n '{alias: "x509-upn", config: {
        "x509-cert-auth.mapping-source-selection": "Match SubjectDN using regular expression",
        "x509-cert-auth.regular-expression": "CN=([^@,]+)@tcn\\.trinitytechnicalservices\\.com",
        "x509-cert-auth.mapper-selection": "Username or Email",
        "x509-cert-auth.extendedkeyusage": "1.3.6.1.5.5.7.3.2",
        "x509-cert-auth.crl-checking-enabled": "false",
        "x509-cert-auth.crldp-checking-enabled": "false",
        "x509-cert-auth.ocsp-checking-enabled": "false",
        "x509-cert-auth.timestamp-validation-enabled": "true",
        "x509-cert-auth.confirmation-page-disallowed": "false"}}' > "${W}/config.json"
    api POST "/authentication/executions/${step}/config" "${W}/config.json" > /dev/null
fi
echo '{"browserFlow":"browser-x509"}' > "${W}/realm.json"
api PUT "" "${W}/realm.json" > /dev/null
[[ "$(api GET "" | jq -r .browserFlow)" == browser-x509 ]] || { echo "ERROR: the realm's browser flow is not browser-x509" >&2; exit 1; }
echo "Certificate sign-in ready: realm tcn uses browser-x509 ($(executions | jq -r '[.[] | select(.level == 0) | .displayName] | join(" -> ")'))."
