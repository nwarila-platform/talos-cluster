#!/usr/bin/env bash
# =============================================================================
# check-no-placeholder-leak.sh - Ensure rendered tenant output has no template
# placeholders left behind.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TENANTS_DIR="${ROOT_DIR}/clusters/talos-cluster/tenants"
PLACEHOLDER_MESSAGE="unresolved template placeholder in rendered output -- a tenant overlay likely includes the zero-touch base but omits a replacement block; this would pass Kyverno's shape regex but fail VSO auth at runtime"

failures=0

render_and_check() {
    local label="$1"
    local path="$2"
    local rendered
    rendered="$(mktemp)"

    if ! kubectl kustomize "${path}" > "${rendered}"; then
        echo "ERROR: failed to render ${label}" >&2
        rm -f "${rendered}"
        return 1
    fi

    if grep -q "placeholder" "${rendered}"; then
        echo "ERROR: ${label}: ${PLACEHOLDER_MESSAGE}" >&2
        grep -n "placeholder" "${rendered}" >&2
        failures=1
    fi

    rm -f "${rendered}"
}

render_and_check "cluster aggregate (clusters/talos-cluster)" "${ROOT_DIR}/clusters/talos-cluster"

for kustomization in "${TENANTS_DIR}"/*/kustomization.yaml; do
    [[ -e "${kustomization}" ]] || continue

    tenant_dir="$(dirname "${kustomization}")"
    tenant="$(basename "${tenant_dir}")"
    if [[ "${tenant}" == "_template" ]]; then
        continue
    fi

    relative_tenant_dir="${tenant_dir#"${ROOT_DIR}/"}"
    render_and_check "tenant ${tenant} (${relative_tenant_dir})" "${tenant_dir}"
done

if [[ "${failures}" -ne 0 ]]; then
    echo "ERROR: ${PLACEHOLDER_MESSAGE}" >&2
    exit 1
fi
