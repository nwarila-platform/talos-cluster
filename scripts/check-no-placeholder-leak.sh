#!/usr/bin/env bash
# =============================================================================
# check-no-placeholder-leak.sh - Ensure cluster, Flux-child, and tenant renders
# have no template placeholders left behind.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TENANTS_DIR="${ROOT_DIR}/clusters/talos-cluster/tenants"
APPS_DIR="${ROOT_DIR}/clusters/talos-cluster/apps"
PLACEHOLDER_MESSAGE="unresolved template placeholder in rendered output -- an overlay or component omitted a required replacement; kustomize accepts the token but the applied workload would be misconfigured"

failures=0

render_and_check() {
    local label="$1"
    local path="$2"
    local rendered
    rendered="$(mktemp)"

    echo "check-no-placeholder-leak: rendering ${label}"
    if ! kubectl kustomize "${path}" > "${rendered}"; then
        echo "ERROR: failed to render ${label}" >&2
        rm -f "${rendered}"
        return 1
    fi

    if grep -qi "placeholder" "${rendered}"; then
        echo "ERROR: ${label}: ${PLACEHOLDER_MESSAGE}" >&2
        grep -ni "placeholder" "${rendered}" >&2
        failures=1
    fi

    rm -f "${rendered}"
}

render_and_check "cluster aggregate (clusters/talos-cluster)" "${ROOT_DIR}/clusters/talos-cluster"

flux_paths="$(mktemp)"
if ! python3 - "${APPS_DIR}" > "${flux_paths}" <<'PY'
from pathlib import Path
import sys

import yaml

apps = Path(sys.argv[1])
candidates = sorted(apps.glob("kustomization-*.yaml"))
vault = apps / "vault-kustomization.yaml"
if vault.is_file():
    candidates.append(vault)

for manifest in candidates:
    for document in yaml.safe_load_all(manifest.read_text(encoding="utf-8")):
        if not isinstance(document, dict) or document.get("kind") != "Kustomization":
            continue
        spec = document.get("spec")
        path = spec.get("path") if isinstance(spec, dict) else None
        if not isinstance(path, str) or not path:
            raise SystemExit(f"{manifest}: Kustomization spec.path is missing")
        relative = path.removeprefix("./")
        resolved = (apps.parents[2] / relative).resolve()
        try:
            resolved.relative_to(apps.parents[2].resolve())
        except ValueError:
            raise SystemExit(f"{manifest}: spec.path escapes the repository: {path}")
        print(path)
PY
then
    echo "ERROR: failed to enumerate Flux child Kustomization paths" >&2
    rm -f "${flux_paths}"
    exit 1
fi

while IFS= read -r flux_path; do
    [[ -n "${flux_path}" ]] || continue
    relative_flux_path="${flux_path#./}"
    render_and_check "Flux child ${flux_path}" "${ROOT_DIR}/${relative_flux_path}"
done < "${flux_paths}"
rm -f "${flux_paths}"

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

echo "check-no-placeholder-leak: OK"
