#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

for script in "${ROOT_DIR}"/scripts/*.sh; do
    bash -n "${script}"
done

if command -v shellcheck >/dev/null; then
    shellcheck -x "${ROOT_DIR}"/scripts/*.sh
fi

if command -v yamllint >/dev/null; then
    yamllint -d '{extends: default, rules: {line-length: {max: 200}, document-start: disable, truthy: {check-keys: false}}}' \
        "${ROOT_DIR}/cluster" "${ROOT_DIR}/platform" "${ROOT_DIR}/.github/workflows"
fi

if command -v actionlint >/dev/null; then
    actionlint "${ROOT_DIR}"/.github/workflows/*.yaml
fi

if command -v kubectl >/dev/null; then
    kubectl kustomize "${ROOT_DIR}/platform/vault" >/dev/null
fi

STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
shopt -s nullglob
configs=("${STATE_ROOT}"/generated/controlplane/*.yaml "${STATE_ROOT}"/generated/worker/*.yaml)
if (( ${#configs[@]} == 0 )); then
    echo "Tracked files are valid. Run 'make generate validate' to also validate Talos configs."
    exit 0
fi

for config in "${configs[@]}"; do
    talosctl validate --config "${config}" --mode metal --strict
done

echo "Tracked files and generated Talos configs are valid."
