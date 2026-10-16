#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

for command in shellcheck yamllint actionlint kubectl python3 terraform; do
    command -v "${command}" >/dev/null || {
        echo "ERROR: ${command} is required (make init)" >&2
        exit 1
    }
done

for script in "${ROOT_DIR}"/scripts/*.sh "${ROOT_DIR}"/scripts/tests/*.sh; do
    bash -n "${script}"
done

shellcheck -x "${ROOT_DIR}"/scripts/*.sh "${ROOT_DIR}"/scripts/tests/*.sh
# The unsealer runs under the Vault image's BusyBox sh, so it is checked as POSIX sh.
shellcheck -s sh "${ROOT_DIR}/platform/vault/unsealer.sh"

python3 -I - "${ROOT_DIR}"/scripts/tests/*.py <<'PY'
import ast
import sys

for filename in sys.argv[1:]:
    with open(filename, encoding="utf-8") as stream:
        ast.parse(stream.read(), filename)
PY

yamllint -d '{extends: default, rules: {line-length: {max: 200}, document-start: disable, truthy: {check-keys: false}}}' \
    "${ROOT_DIR}/cluster" "${ROOT_DIR}/platform" "${ROOT_DIR}/examples" "${ROOT_DIR}/.github/workflows"

actionlint "${ROOT_DIR}"/.github/workflows/*.yaml

kubectl kustomize "${ROOT_DIR}/platform/vault" >/dev/null

# Terraform: formatting and a provider-schema validation of every root.
# Providers are installed into a cache directory under HOME because /tmp may
# be noexec; each root keeps its own data directory.
for root in gitlab-vault cloudflare; do
    terraform -chdir="${ROOT_DIR}/terraform/${root}" fmt -check -recursive
    tf_data="${XDG_CACHE_HOME:-${HOME}/.cache}/talos-cluster-validate/terraform-${root}"
    mkdir -p "${tf_data}"
    TF_DATA_DIR="${tf_data}" terraform -chdir="${ROOT_DIR}/terraform/${root}" init \
        -backend=false -input=false -lockfile=readonly >/dev/null
    TF_DATA_DIR="${tf_data}" terraform -chdir="${ROOT_DIR}/terraform/${root}" validate
done

STATE_ROOT="${STATE_DIR_OVERRIDE:-${ROOT_DIR}/${STATE_DIR}}"
shopt -s nullglob
configs=("${STATE_ROOT}"/generated/controlplane/*.yaml "${STATE_ROOT}"/generated/worker/*.yaml)
if (( ${#configs[@]} == 0 )); then
    echo "Tracked files are valid. Run 'make generate validate' to also validate Talos configs."
    exit 0
fi

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
