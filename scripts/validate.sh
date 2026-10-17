#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${ROOT_DIR}/cluster/config.env"

for command in shellcheck yamllint actionlint kubectl python3 terraform helm; do
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

# platform/keycloak-operator/upstream is vendored byte-exact (checked below by SHA256SUMS), not linted;
# yamllint's ignore patterns match the paths as given, so the paths are relative to the repository.
(cd "${ROOT_DIR}" && yamllint -d '{extends: default, rules: {line-length: {max: 200}, document-start: disable, truthy: {check-keys: false}}, ignore: "platform/keycloak-operator/upstream/"}' \
    cluster platform examples .github/workflows)

actionlint "${ROOT_DIR}"/.github/workflows/*.yaml

kubectl kustomize "${ROOT_DIR}/platform/vault" >/dev/null
kubectl kustomize "${ROOT_DIR}/platform/keycloak" >/dev/null
# The vendored Keycloak operator must be the recorded upstream bytes, and render.
(cd "${ROOT_DIR}/platform/keycloak-operator/upstream" && sha256sum --check --strict --quiet SHA256SUMS)
kubectl kustomize "${ROOT_DIR}/platform/keycloak-operator" >/dev/null
# Charts are installed by digest: the installer must use the digest variables, never a bare version.
grep -qE 'helm upgrade --install cert-manager "\$\{CERT_MANAGER_CHART\}"' "${ROOT_DIR}/scripts/install-platform.sh" || { echo "ERROR: install-platform.sh must install cert-manager from CERT_MANAGER_CHART (digest)" >&2; exit 1; }
grep -qE 'helm upgrade --install cnpg "\$\{CNPG_CHART\}"' "${ROOT_DIR}/scripts/install-platform.sh" || { echo "ERROR: install-platform.sh must install cnpg from CNPG_CHART (digest)" >&2; exit 1; }
[[ "${CERT_MANAGER_CHART}" =~ ^oci://.+@sha256:[0-9a-f]{64}$ && "${CNPG_CHART}" =~ ^oci://.+@sha256:[0-9a-f]{64}$ ]] || { echo "ERROR: CERT_MANAGER_CHART and CNPG_CHART must be oci://...@sha256:<digest> references" >&2; exit 1; }
# The two charts are rendered from the pinned digests with the release names install-platform.sh
# uses (so the rendered objects carry the installed names), cached under HOME. The renders serve
# two checks: every RBAC object and admission webhook must equal the reviewed fingerprint
# scripts/tests/rbac-accepted.json, with the policy it was accepted under (check-rbac.py: one CNPG
# binding with three Secret-free rule groups, no Keycloak operator ClusterRoleBinding, cert-manager's
# bindings only to its own service accounts, no wildcard rule), and every custom resource is
# pre-checked against the CRD that will admit it (check-crs.py; the live strict server-side dry-run is
# authoritative). The Keycloak CRDs are the vendored ones.
crd_cache="${XDG_CACHE_HOME:-${HOME}/.cache}/talos-cluster-validate/crds"
mkdir -p "${crd_cache}"
cert_manager_render="${crd_cache}/cert-manager-${CERT_MANAGER_CHART##*@sha256:}.yaml"
cnpg_render="${crd_cache}/cnpg-${CNPG_CHART##*@sha256:}.yaml"
if [[ ! -s "${cert_manager_render}" ]]; then
    helm template cert-manager "${CERT_MANAGER_CHART}" --namespace cert-manager --values "${ROOT_DIR}/platform/cert-manager/values.yaml" > "${cert_manager_render}.tmp"
    mv "${cert_manager_render}.tmp" "${cert_manager_render}"
fi
if [[ ! -s "${cnpg_render}" ]]; then
    helm template cnpg "${CNPG_CHART}" --namespace keycloak --values "${ROOT_DIR}/platform/cnpg/values.yaml" > "${cnpg_render}.tmp"
    mv "${cnpg_render}.tmp" "${cnpg_render}"
fi
kubectl kustomize "${ROOT_DIR}/platform/keycloak-operator" > "${crd_cache}/keycloak-operator-render.yaml"
python3 -I "${ROOT_DIR}/scripts/tests/check-rbac.py" --accepted "${ROOT_DIR}/scripts/tests/rbac-accepted.json" \
    --cert-manager "${cert_manager_render}" --cnpg "${cnpg_render}" --keycloak-operator "${crd_cache}/keycloak-operator-render.yaml"
# Every custom resource this piece applies, pre-checked against the served schema of its CRD: a missing
# or ambiguous schema or document is an error, closed objects reject unknown fields, list-type set/map
# uniqueness holds; CEL rules are listed for the live server-side dry-run, which is authoritative.
kubectl kustomize "${ROOT_DIR}/platform/keycloak" > "${crd_cache}/keycloak-render.yaml"
python3 -I "${ROOT_DIR}/scripts/tests/check-crs.py" \
    --require Certificate.cert-manager.io/v1 --require ClusterIssuer.cert-manager.io/v1 \
    --require Cluster.postgresql.cnpg.io/v1 \
    --require Keycloak.k8s.keycloak.org/v2beta1 --require KeycloakRealmImport.k8s.keycloak.org/v2beta1 \
    "${cert_manager_render}" "${cnpg_render}" "${ROOT_DIR}"/platform/keycloak-operator/upstream/keycloak*.yml \
    -- "${crd_cache}/keycloak-render.yaml" "${ROOT_DIR}/platform/keycloak/realm-import.yaml" "${ROOT_DIR}/platform/cert-manager/issuer.yaml"
# The realm import is applied by scripts/keycloak.sh, not by the kustomization: one well-formed
# KeycloakRealmImport, placeholders bound to the realm Secret, the LDAP provider's seven mappers
# byte-exact (check-realm.py holds the expected list).
python3 -I "${ROOT_DIR}/scripts/tests/check-realm.py" "${ROOT_DIR}/platform/keycloak/realm-import.yaml"

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
