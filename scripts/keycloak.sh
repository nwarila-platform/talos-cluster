#!/usr/bin/env bash
# Configures Keycloak after `make platform` and `make gitlab-vault`: builds the realm Secret from
# .state/keycloak/ (fail-closed: a Secret holding different values is refused, never overwritten),
# waits for the Keycloak server to be ready (its certificate comes from the Vault issuer, so
# gitlab-vault must have run), imports the tcn realm once from platform/keycloak/realm-import.yaml,
# waits for the import to finish, and prints the remaining owner steps. Secret values travel to
# kubectl as files, never as arguments, and are never printed. Rerunnable: a matching Secret and an
# imported realm are left alone.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

if [[ "${CONFIRM_REBUILD:-}" != "TDNHQ-TALCL01" ]]; then
    echo "ERROR: set CONFIRM_REBUILD=TDNHQ-TALCL01 to authorize Keycloak configuration" >&2
    exit 1
fi

for command in jq kubectl openssl; do
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
KC_DIR="${STATE_ROOT}/keycloak"
REALM_FILE="${ROOT_DIR}/platform/keycloak/realm-import.yaml"
POLL_SECONDS="${KEYCLOAK_POLL_SECONDS:-10}"
IMPORT_TIMEOUT="${KEYCLOAK_IMPORT_TIMEOUT:-600}"
umask 077
mkdir -p "${KC_DIR}"

# Values this script owns are generated once; the Active Directory bind password is produced by
# the directory tooling when the svc-keycloak account is created, and must already be here.
generate_if_absent() {  # generate_if_absent FILE
    [[ -s "$1" ]] && return 0
    openssl rand -base64 36 | tr -d '\n' > "$1.tmp"
    chmod 0600 "$1.tmp"
    mv -T "$1.tmp" "$1"
    echo "generated $1"
}
generate_if_absent "${KC_DIR}/admin.password"
generate_if_absent "${KC_DIR}/gitlab-client.secret"
[[ -s "${KC_DIR}/svc-keycloak.password" ]] || {
    echo "ERROR: ${KC_DIR}/svc-keycloak.password is missing: create the Active Directory bind account first (README: Keycloak)" >&2
    exit 1
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir:?}"' EXIT
key_dir="${work_dir}/keys"
mkdir -m 0700 "${key_dir}"
# Each value becomes a Secret key the import job substitutes into the realm JSON as text, so it
# must be one line of characters that cannot break a JSON string: no quotes, no backslashes.
copy_value() {  # copy_value KEY FILE
    [[ "$(stat -c %a "$2")" == "600" ]] || { echo "ERROR: $2 must be mode 0600 (chmod 0600 it; it is a secret)" >&2; exit 1; }
    if ! { [[ "$(wc -l < "$2")" == "0" ]] && grep -qxE '[A-Za-z0-9+/=._-]{16,}' "$2"; }; then
        echo "ERROR: $2 must be a single line of at least 16 characters from A-Za-z0-9+/=._- (no newline)" >&2
        exit 1
    fi
    cp "$2" "${key_dir}/$1"
}
copy_value ADMIN_PASSWORD "${KC_DIR}/admin.password"
copy_value LDAP_BIND_PASSWORD "${KC_DIR}/svc-keycloak.password"
copy_value GITLAB_CLIENT_SECRET "${KC_DIR}/gitlab-client.secret"

if ! existing="$(kubectl -n keycloak get secret keycloak-realm-secrets --ignore-not-found -o json 2> "${work_dir}/get.err")"; then
    echo "ERROR: could not read secret keycloak/keycloak-realm-secrets (not deciding presence): $(tr '\n' ' ' < "${work_dir}/get.err")" >&2
    exit 1
fi
if [[ -n "${existing}" ]]; then
    jq -e '(.data | type) == "object" and (.data | keys) == ["ADMIN_PASSWORD", "GITLAB_CLIENT_SECRET", "LDAP_BIND_PASSWORD"]' \
        <<<"${existing}" >/dev/null 2>&1 || {
        echo "ERROR: secret keycloak/keycloak-realm-secrets has an unexpected shape; inspect it before continuing" >&2
        exit 1
    }
    for key in ADMIN_PASSWORD LDAP_BIND_PASSWORD GITLAB_CLIENT_SECRET; do
        expected="$(base64 -w0 < "${key_dir}/${key}")"
        actual="$(jq -r --arg k "${key}" '.data[$k]' <<<"${existing}")"
        [[ "${expected}" == "${actual}" ]] || {
            echo "ERROR: secret keycloak/keycloak-realm-secrets does not match the values in ${KC_DIR} (${key}); rotate deliberately: delete the Secret, update Keycloak, then rerun" >&2
            exit 1
        }
    done
    echo "Secret keycloak/keycloak-realm-secrets already holds the values from ${KC_DIR}; left unchanged."
else
    kubectl -n keycloak create secret generic keycloak-realm-secrets --from-file="${key_dir}"
    echo "Secret keycloak/keycloak-realm-secrets created from ${KC_DIR}."
fi

kubectl -n keycloak get keycloak keycloak -o name >/dev/null || {
    echo "ERROR: the Keycloak resource keycloak/keycloak does not exist; run make platform first" >&2
    exit 1
}
kubectl -n keycloak wait keycloak/keycloak --for=condition=Ready --timeout=15m || {
    echo "ERROR: Keycloak is not ready; check the keycloak-tls Certificate (make gitlab-vault configures its issuer), keycloak-db and the keycloak-0 pod" >&2
    exit 1
}

if ! current="$(kubectl -n keycloak get keycloakrealmimport tcn --ignore-not-found -o json 2> "${work_dir}/get.err")"; then
    echo "ERROR: could not read keycloakrealmimport keycloak/tcn (not deciding presence): $(tr '\n' ' ' < "${work_dir}/get.err")" >&2
    exit 1
fi
condition() {  # condition JSON TYPE -> the condition's status, or empty
    jq -r --arg t "$2" '[.status.conditions[]? | select(.type == $t) | .status | tostring][0] // ""' <<<"$1"
}
if [[ -n "${current}" ]]; then
    [[ "$(condition "${current}" Done)" == "True" ]] || {
        echo "ERROR: keycloakrealmimport keycloak/tcn exists but is not Done: $(jq -c '.status.conditions // []' <<<"${current}"); inspect it and its job before rerunning" >&2
        exit 1
    }
    echo "Realm tcn already imported; left unchanged."
else
    # The API server checks the object first (schema, unknown fields, CEL rules) without persisting it; a
    # rejected dry-run creates nothing.
    if ! kubectl create --dry-run=server --validate=strict -f "${REALM_FILE}" > "${work_dir}/dry-run.out" 2>&1; then
        echo "ERROR: the API server rejected the realm import in a strict server-side dry-run: $(tr '\n' ' ' < "${work_dir}/dry-run.out")" >&2
        exit 1
    fi
    kubectl create -f "${REALM_FILE}"
    deadline=$(( SECONDS + IMPORT_TIMEOUT ))
    while :; do
        current="$(kubectl -n keycloak get keycloakrealmimport tcn -o json)"
        if [[ "$(condition "${current}" HasErrors)" == "True" ]]; then
            echo "ERROR: the realm import failed: $(jq -c '.status.conditions // []' <<<"${current}")" >&2
            exit 1
        fi
        [[ "$(condition "${current}" Done)" == "True" ]] && break
        (( SECONDS < deadline )) || { echo "ERROR: the realm import did not finish within ${IMPORT_TIMEOUT}s" >&2; exit 1; }
        sleep "${POLL_SECONDS}"
    done
    echo "Realm tcn imported."
fi

cat <<EOT
Keycloak is configured.
  Admin console (master realm): https://keycloak.trinitytechnicalservices.com/admin/ as temp-admin; the password is in the
    keycloak/keycloak-initial-admin Secret (kubectl -n keycloak get secret keycloak-initial-admin -o jsonpath='{.data.password}' | base64 -d).
  Realm tcn administrator: tcn-admin, password in ${KC_DIR}/admin.password (change it at first login).
  GitLab: install the PKI root (configmap keycloak/root-ca) and the OmniAuth block from platform/gitlab-host/gitlab.rb.keycloak (README: Keycloak);
    the client secret is ${KC_DIR}/gitlab-client.secret.
  Site resolver: host override keycloak.trinitytechnicalservices.com -> ${CLUSTER_VIP} (README: Keycloak).
EOT
