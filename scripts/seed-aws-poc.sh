#!/usr/bin/env bash
set -euo pipefail

for command in vault jq; do
    command -v "${command}" >/dev/null || { echo "ERROR: ${command} is required" >&2; exit 1; }
done

: "${VAULT_ADDR:?set VAULT_ADDR}"
: "${VAULT_CACERT:?set VAULT_CACERT}"
: "${VAULT_TOKEN:?set VAULT_TOKEN}"
: "${GITLAB_PROJECT_ID:?set GITLAB_PROJECT_ID}"
: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID}"
: "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY}"
: "${AWS_REGION:?set AWS_REGION}"
[[ "${GITLAB_PROJECT_ID}" =~ ^[0-9]+$ ]] || { echo "ERROR: GITLAB_PROJECT_ID must be numeric" >&2; exit 1; }

jq -n \
    '{AWS_ACCESS_KEY_ID:env.AWS_ACCESS_KEY_ID,
      AWS_SECRET_ACCESS_KEY:env.AWS_SECRET_ACCESS_KEY,
      AWS_SESSION_TOKEN:(env.AWS_SESSION_TOKEN // ""),
      AWS_REGION:env.AWS_REGION}' \
    | vault kv put -mount=kv "ci/production/project-${GITLAB_PROJECT_ID}/aws" -

echo "Seeded the dedicated PoC credential at the project-scoped path."
