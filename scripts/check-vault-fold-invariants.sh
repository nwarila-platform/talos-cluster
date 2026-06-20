#!/usr/bin/env bash
# =============================================================================
# check-vault-fold-invariants.sh - Ensure the retired Vault deploy-repo wrapper
# stays folded into the platform-owned apps/vault tree.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VAULT_TENANT="deploy-vault"
RETIRED_APP_DIR="clusters/talos-cluster/apps/${VAULT_TENANT}"
TENANT_DIR="clusters/talos-cluster/tenants/${VAULT_TENANT}"
NAMESPACE_FILE="${TENANT_DIR}/namespace.yaml"
OVERRIDES_FILE="${ROOT_DIR}/cluster/deploy-repo-overrides.sh"
DELIVERY_REINTRODUCED_MESSAGE="deploy-repo delivery re-introduced for deploy-vault; Vault must stay folded into apps/vault"

fail() {
    echo "ERROR: $1" >&2
    exit 1
}

array_contains() {
    local needle="$1"
    shift
    local candidate

    for candidate in "$@"; do
        if [[ "${candidate}" == "${needle}" ]]; then
            return 0
        fi
    done

    return 1
}

cd "${ROOT_DIR}"

if [[ -n "$(git ls-files -- "${RETIRED_APP_DIR}/")" ]]; then
    fail "the retired Vault deploy-repo wrapper was recreated; Vault lives in apps/vault"
fi

while IFS= read -r tracked_file; do
    [[ -f "${tracked_file}" ]] || continue

    if grep -Eq '^[[:space:]]*kind:[[:space:]]*GitRepository([[:space:]]|$)' "${tracked_file}"; then
        fail "${DELIVERY_REINTRODUCED_MESSAGE}"
    fi

    if grep -Eq '^[[:space:]]*sourceRef:' "${tracked_file}"; then
        fail "${DELIVERY_REINTRODUCED_MESSAGE}"
    fi
done < <(git ls-files -- "${TENANT_DIR}/")

if git ls-files --error-unmatch "${NAMESPACE_FILE}" >/dev/null 2>&1 && [[ -f "${NAMESPACE_FILE}" ]]; then
    declare -a DEPLOY_REPO_RETAINED_TENANTS=()
    declare -a DEPLOY_REPO_DISCOVERY_TOMBSTONES=()

    set +u
    # shellcheck source=../cluster/deploy-repo-overrides.sh
    # shellcheck disable=SC1091
    source "${OVERRIDES_FILE}"
    set -u

    if ! array_contains "${VAULT_TENANT}" "${DEPLOY_REPO_RETAINED_TENANTS[@]}"; then
        fail "deploy-vault namespace would be pruned on next generator run"
    fi

    if ! array_contains "${VAULT_TENANT}" "${DEPLOY_REPO_DISCOVERY_TOMBSTONES[@]}"; then
        fail "retired wrapper could be re-adopted by discovery"
    fi
fi

echo "OK: Vault fold invariants hold."