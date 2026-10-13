#!/usr/bin/env bash
set -euo pipefail

for command in vault jq; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

: "${VAULT_ADDR:?set VAULT_ADDR to the Vault NodePort URL}"
: "${VAULT_CACERT:?set VAULT_CACERT to the Vault CA file}"
: "${VAULT_TOKEN:?set VAULT_TOKEN to an administrative token}"
: "${GITLAB_URL:?set GITLAB_URL, including https:// and without a trailing slash}"
: "${GITLAB_PROJECT_ID:?set the numeric GitLab project ID}"
: "${VAULT_AUDIENCE:?set the exact audience requested by the GitLab ID token}"

[[ "${GITLAB_URL}" == https://* && "${GITLAB_URL}" != */ ]] || {
    echo "ERROR: GITLAB_URL must be https://... with no trailing slash" >&2
    exit 1
}
[[ "${GITLAB_PROJECT_ID}" =~ ^[0-9]+$ ]] || { echo "ERROR: GITLAB_PROJECT_ID must be numeric" >&2; exit 1; }
[[ -r "${VAULT_CACERT}" ]] || { echo "ERROR: cannot read VAULT_CACERT" >&2; exit 1; }

if ! vault secrets list -format=json | jq -e 'has("kv/")' >/dev/null; then
    vault secrets enable -path=kv kv-v2
fi
if ! vault auth list -format=json | jq -e 'has("gitlab/")' >/dev/null; then
    vault auth enable -path=gitlab jwt
fi

config_args=("oidc_discovery_url=${GITLAB_URL}" "bound_issuer=${GITLAB_URL}")
if [[ -n "${GITLAB_CA_FILE:-}" ]]; then
    [[ -r "${GITLAB_CA_FILE}" ]] || { echo "ERROR: cannot read GITLAB_CA_FILE" >&2; exit 1; }
    config_args+=("oidc_discovery_ca_pem=@${GITLAB_CA_FILE}")
fi
vault write auth/gitlab/config "${config_args[@]}"

policy_name="ci-project-${GITLAB_PROJECT_ID}-aws-read"
role_name="ci-project-${GITLAB_PROJECT_ID}"
policy_file="$(mktemp)"
role_file="$(mktemp)"
trap 'rm -f "${policy_file}" "${role_file}"' EXIT
chmod 0600 "${policy_file}" "${role_file}"

printf 'path "kv/data/ci/production/project-%s/aws" {\n  capabilities = ["read"]\n}\n' \
    "${GITLAB_PROJECT_ID}" > "${policy_file}"
vault policy write "${policy_name}" "${policy_file}"

jq -n \
    --arg audience "${VAULT_AUDIENCE}" \
    --arg project_id "${GITLAB_PROJECT_ID}" \
    --arg policy "${policy_name}" \
    '{role_type:"jwt", bound_audiences:[$audience], user_claim:"project_id",
      bound_claims_type:"string",
      bound_claims:{project_id:$project_id, ref:"main", ref_type:"branch", ref_protected:"true"},
      token_policies:[$policy], token_no_default_policy:true,
      token_ttl:"10m", token_explicit_max_ttl:"10m"}' > "${role_file}"
vault write "auth/gitlab/role/${role_name}" @"${role_file}"

echo "Configured Vault role ${role_name}; no AWS credential has been written."
