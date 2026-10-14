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

command -v python3 >/dev/null || {
    echo "ERROR: python3 and PyYAML are required to validate generated configs" >&2
    exit 1
}
python3 -I -c 'import yaml' >/dev/null 2>&1 || {
    echo "ERROR: python3 PyYAML is required to validate generated configs" >&2
    exit 1
}
python3 -I - "${configs[@]}" <<'PY'
import sys

import yaml


def walk(obj, path):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from walk(value, f"{path}.{key}")
    elif isinstance(obj, list):
        scalars = [value for value in obj if not isinstance(value, (dict, list))]
        duplicates = {value for value in scalars if scalars.count(value) > 1}
        if duplicates:
            yield path, sorted(map(str, duplicates))
        for index, value in enumerate(obj):
            yield from walk(value, f"{path}[{index}]")


failed = False
for filename in sys.argv[1:]:
    with open(filename, encoding="utf-8") as stream:
        for document, data in enumerate(yaml.safe_load_all(stream)):
            for path, duplicates in walk(data, "$"):
                print(
                    f"ERROR: {filename}: document {document}: {path}: "
                    f"duplicate scalar values: {', '.join(duplicates)}",
                    file=sys.stderr,
                )
                failed = True

if failed:
    sys.exit(1)
PY

for config in "${configs[@]}"; do
    talosctl validate --config "${config}" --mode metal --strict
done

echo "Tracked files and generated Talos configs are valid."
