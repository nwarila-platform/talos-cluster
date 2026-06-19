#!/usr/bin/env bash
# =============================================================================
# sync-deploy-repos.sh - Generate zero-touch tenant overlays for deploy-* repos.
#
# Convention-discovered repositories are admitted only when all of these are true:
#   1. name matches deploy-*
#   2. repository is not archived
#   3. repository exposes kubernetes/overlays/talos-cluster/kustomization.yaml
#   4. cluster/deploy-repo-overrides.sh registers an orgPrefix for the repo
#
# Explicit tenants in cluster/deploy-repo-overrides.sh use the same renderer for
# reviewed cross-org or private sources that cannot be discovered by convention.
# Generated tenants are named <orgPrefix>-<repo-databaseId>; the human repo name,
# source org, and databaseId are carried as Namespace labels.
#
# By default, discovery uses the GitHub CLI. For deterministic local tests, set
# DEPLOY_REPOS to a comma or whitespace separated list of repository names and
# provide DEPLOY_REPO_DATABASE_ID_OVERRIDES plus DEPLOY_REPO_ORG_PREFIX_OVERRIDES.
# Set DEPLOY_REPO_EXPLICIT_ONLY=true to render only explicit tenants and skip
# both convention discovery and the GitHub scan.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ORG="${DEPLOY_REPO_ORG:-nwarila-platform}"
PREFIX="${DEPLOY_REPO_PREFIX:-deploy-}"
MANIFEST_PATH="${DEPLOY_REPO_PATH:-kubernetes/overlays/talos-cluster}"
LIMIT="${DEPLOY_REPO_LIMIT:-1000}"
INCLUDE_PRIVATE="${DEPLOY_REPO_INCLUDE_PRIVATE:-false}"
EXPLICIT_ONLY="${DEPLOY_REPO_EXPLICIT_ONLY:-false}"

TENANTS_DIR="${DEPLOY_TENANTS_DIR:-${ROOT_DIR}/clusters/talos-cluster/tenants}"
TENANT_TEMPLATE_DIR="${DEPLOY_TENANT_TEMPLATE_DIR:-${TENANTS_DIR}/_template}"
ZERO_TOUCH_BASE_DIR="${TENANT_TEMPLATE_DIR}/zero-touch/base"
TENANTS_KUSTOMIZATION="${DEPLOY_TENANTS_KUSTOMIZATION:-${TENANTS_DIR}/kustomization.yaml}"
OVERRIDES_FILE="${DEPLOY_REPO_OVERRIDES_FILE:-${ROOT_DIR}/cluster/deploy-repo-overrides.sh}"
ORG_PULL_AUTH_DIR="${DEPLOY_ORG_PULL_AUTH_DIR:-${ROOT_DIR}/clusters/talos-cluster/apps/vault-secrets-operator/org-pull}"

NAME_RE="^${PREFIX}[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
TENANT_RE="^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
GENERATED_TENANT_RE="^[a-z0-9]([-a-z0-9]*[a-z0-9])?-[0-9]+$"
ORG_PREFIX_RE="^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
COMMIT_RE="^[0-9a-f]{40}$"
DATABASE_ID_RE="^[0-9]+$"

# Defaults only. cluster/deploy-repo-overrides.sh may replace or append to them.
declare -a EXPLICIT_DEPLOY_TENANTS=()
declare -A DEPLOY_REPO_BRANCH_OVERRIDES=()
declare -A DEPLOY_REPO_SOURCE_ORG_OVERRIDES=()
declare -A DEPLOY_REPO_SOURCE_NAME_OVERRIDES=()
declare -A DEPLOY_REPO_MANIFEST_PATH_OVERRIDES=()
declare -A DEPLOY_REPO_REF_KIND_OVERRIDES=()
declare -A DEPLOY_REPO_REF_OVERRIDES=()
declare -A DEPLOY_REPO_ORG_PREFIX_OVERRIDES=()
declare -A DEPLOY_REPO_DATABASE_ID_OVERRIDES=()
declare -a PLATFORM_CRITICAL_DEPLOY_REPOS=()
declare -a DEPLOY_REPO_DISCOVERY_TOMBSTONES=()
declare -a DEPLOY_REPO_RETAINED_TENANTS=()

if [[ -f "${OVERRIDES_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${OVERRIDES_FILE}"
elif [[ -n "${DEPLOY_REPO_OVERRIDES_FILE:-}" ]]; then
    echo "ERROR: DEPLOY_REPO_OVERRIDES_FILE not found: ${OVERRIDES_FILE}" >&2
    exit 1
fi

array_contains() {
    local needle="$1"
    shift
    local item

    for item in "$@"; do
        if [[ "${item}" == "${needle}" ]]; then
            return 0
        fi
    done
    return 1
}

require_file() {
    local path="$1"
    if [[ ! -f "${path}" ]]; then
        echo "ERROR: required file not found: ${path}" >&2
        exit 1
    fi
}

require_dir() {
    local path="$1"
    if [[ ! -d "${path}" ]]; then
        echo "ERROR: required directory not found: ${path}" >&2
        exit 1
    fi
}

is_discovery_tombstoned() {
    local name="$1"

    array_contains "${name}" "${DEPLOY_REPO_DISCOVERY_TOMBSTONES[@]}"
}

is_retained_tenant() {
    local tenant="$1"

    array_contains "${tenant}" "${DEPLOY_REPO_RETAINED_TENANTS[@]}"
}

is_managed_tenant_entry() {
    local entry="$1"

    if [[ "${entry}" =~ ${GENERATED_TENANT_RE} ]]; then
        return 0
    fi
    if [[ "${entry}" =~ ${NAME_RE} ]] && ! is_retained_tenant "${entry}"; then
        return 0
    fi
    return 1
}

validate_ref() {
    local name="$1"
    local ref_kind="$2"
    local ref_value="$3"

    if [[ "${ref_kind}" != "branch" && "${ref_kind}" != "tag" && "${ref_kind}" != "commit" ]]; then
        echo "ERROR: unsupported GitRepository ref kind for ${name}: ${ref_kind}" >&2
        exit 1
    fi
    if [[ -z "${ref_value}" ]]; then
        echo "ERROR: GitRepository ref value for ${name} must not be empty" >&2
        exit 1
    fi
    if [[ "${ref_kind}" == "commit" && ! "${ref_value}" =~ ${COMMIT_RE} ]]; then
        echo "ERROR: commit ref for ${name} must be a 40-character SHA: ${ref_value}" >&2
        exit 1
    fi
}

validate_platform_critical_overrides() {
    local repo
    local ref_kind
    local ref_value

    for repo in "${PLATFORM_CRITICAL_DEPLOY_REPOS[@]}"; do
        if ! [[ "${repo}" =~ ${TENANT_RE} ]]; then
            echo "ERROR: platform-critical deploy repo key does not match ${TENANT_RE}: ${repo}" >&2
            exit 1
        fi

        ref_kind="${DEPLOY_REPO_REF_KIND_OVERRIDES[${repo}]:-}"
        ref_value="${DEPLOY_REPO_REF_OVERRIDES[${repo}]:-}"

        if [[ -z "${ref_kind}" || -z "${ref_value}" ]]; then
            echo "ERROR: platform-critical deploy repo ${repo} must set an immutable ref override" >&2
            exit 1
        fi
        if [[ "${ref_kind}" != "commit" && "${ref_kind}" != "tag" ]]; then
            echo "ERROR: platform-critical deploy repo ${repo} must use ref kind commit or tag" >&2
            exit 1
        fi
        validate_ref "${repo}" "${ref_kind}" "${ref_value}"
    done
}

validate_override_lists() {
    local repo
    local tenant

    for repo in "${DEPLOY_REPO_DISCOVERY_TOMBSTONES[@]}"; do
        if ! [[ "${repo}" =~ ${NAME_RE} ]]; then
            echo "ERROR: deploy repo discovery tombstone does not match ${NAME_RE}: ${repo}" >&2
            exit 1
        fi
    done

    for tenant in "${DEPLOY_REPO_RETAINED_TENANTS[@]}"; do
        if ! [[ "${tenant}" =~ ${TENANT_RE} ]]; then
            echo "ERROR: retained deploy tenant does not match ${TENANT_RE}: ${tenant}" >&2
            exit 1
        fi
    done
}

validate_org_prefix() {
    local name="$1"
    local org_prefix="$2"
    local auth_path

    if [[ -z "${org_prefix}" ]]; then
        echo "ERROR: deploy repo ${name} must set DEPLOY_REPO_ORG_PREFIX_OVERRIDES[${name}]" >&2
        exit 1
    fi
    if ! [[ "${org_prefix}" =~ ${ORG_PREFIX_RE} ]]; then
        echo "ERROR: orgPrefix for ${name} must match ${ORG_PREFIX_RE}: ${org_prefix}" >&2
        exit 1
    fi

    auth_path="${ORG_PULL_AUTH_DIR}/vaultauth-org-pull-${org_prefix}.yaml"
    if [[ ! -f "${auth_path}" ]]; then
        echo "ERROR: unprovisioned orgPrefix for ${name}: ${org_prefix}; missing ${auth_path}" >&2
        exit 1
    fi
}

resolve_database_id() {
    local name="$1"
    local source_org="$2"
    local source_name="$3"
    local discovered_database_id="$4"
    local database_id="${DEPLOY_REPO_DATABASE_ID_OVERRIDES[${name}]:-${discovered_database_id}}"

    if [[ -z "${database_id}" ]]; then
        if ! command -v gh >/dev/null 2>&1; then
            echo "ERROR: databaseId for ${name} is unresolved and gh is unavailable; set DEPLOY_REPO_DATABASE_ID_OVERRIDES[${name}]" >&2
            exit 1
        fi
        if ! database_id="$(gh api "repos/${source_org}/${source_name}" --jq '.id')"; then
            echo "ERROR: failed to resolve databaseId for ${source_org}/${source_name}; set DEPLOY_REPO_DATABASE_ID_OVERRIDES[${name}]" >&2
            exit 1
        fi
    fi

    if ! [[ "${database_id}" =~ ${DATABASE_ID_RE} ]]; then
        echo "ERROR: databaseId for ${name} must be all digits: ${database_id}" >&2
        exit 1
    fi
    printf '%s\n' "${database_id}"
}

generated_path_is_trackable() {
    local tenant_id="$1"
    local default_tenants_dir="${ROOT_DIR}/clusters/talos-cluster/tenants"
    local tenant_path="clusters/talos-cluster/tenants/${tenant_id}/kustomization.yaml"

    if [[ "${TENANTS_DIR}" != "${default_tenants_dir}" ]]; then
        return 0
    fi
    if ! git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        return 0
    fi
    if git -C "${ROOT_DIR}" check-ignore -q -- "${tenant_path}"; then
        return 1
    fi
    return 0
}

require_dir "${TENANTS_DIR}"
require_dir "${ZERO_TOUCH_BASE_DIR}"
require_dir "${ORG_PULL_AUTH_DIR}"
require_file "${TENANTS_KUSTOMIZATION}"

if [[ "${INCLUDE_PRIVATE}" != "true" && "${INCLUDE_PRIVATE}" != "false" ]]; then
    echo "ERROR: DEPLOY_REPO_INCLUDE_PRIVATE must be true or false" >&2
    exit 1
fi
if [[ "${EXPLICIT_ONLY}" != "true" && "${EXPLICIT_ONLY}" != "false" ]]; then
    echo "ERROR: DEPLOY_REPO_EXPLICIT_ONLY must be true or false" >&2
    exit 1
fi

validate_platform_critical_overrides
validate_override_lists

declare -A REF_KIND_BY_REPO=()
declare -A REF_VALUE_BY_REPO=()
declare -A SOURCE_ORG_BY_REPO=()
declare -A SOURCE_NAME_BY_REPO=()
declare -A MANIFEST_PATH_BY_REPO=()
declare -A ORG_PREFIX_BY_REPO=()
declare -A DATABASE_ID_BY_REPO=()
declare -A TENANT_ID_BY_REPO=()
declare -A REPO_BY_TENANT_ID=()
deploy_repos=()

add_repo() {
    local name="$1"
    local branch="${2:-main}"
    local source_org="${3:-${ORG}}"
    local source_name="${4:-${name}}"
    local manifest_path="${5:-${MANIFEST_PATH}}"
    local discovered_database_id="${6:-}"
    local admission_mode="${7:-convention}"
    local ref_kind="${DEPLOY_REPO_REF_KIND_OVERRIDES[${name}]:-branch}"
    local ref_value="${DEPLOY_REPO_REF_OVERRIDES[${name}]:-${branch:-main}}"
    local org_prefix="${DEPLOY_REPO_ORG_PREFIX_OVERRIDES[${name}]:-}"
    local database_id
    local tenant_id

    if [[ "${admission_mode}" == "convention" ]] && ! [[ "${name}" =~ ${NAME_RE} ]]; then
        echo "ERROR: deploy repo name does not match ${NAME_RE}: ${name}" >&2
        exit 1
    fi
    if [[ "${admission_mode}" == "explicit" ]] && ! [[ "${name}" =~ ${TENANT_RE} ]]; then
        echo "ERROR: explicit tenant key does not match ${TENANT_RE}: ${name}" >&2
        exit 1
    fi
    if ! [[ "${source_name}" =~ ${NAME_RE} ]]; then
        echo "ERROR: source deploy repo name for ${name} does not match ${NAME_RE}: ${source_name}" >&2
        exit 1
    fi

    validate_ref "${name}" "${ref_kind}" "${ref_value}"
    validate_org_prefix "${name}" "${org_prefix}"
    database_id="$(resolve_database_id "${name}" "${source_org}" "${source_name}" "${discovered_database_id}")"
    tenant_id="${org_prefix}-${database_id}"

    if ! [[ "${tenant_id}" =~ ${GENERATED_TENANT_RE} ]]; then
        echo "ERROR: generated tenant id for ${name} is invalid: ${tenant_id}" >&2
        exit 1
    fi
    if ! generated_path_is_trackable "${tenant_id}"; then
        echo "ERROR: generated tenant path is ignored by .gitignore: clusters/talos-cluster/tenants/${tenant_id}/kustomization.yaml" >&2
        exit 1
    fi
    if [[ -n "${REPO_BY_TENANT_ID[${tenant_id}]:-}" && "${REPO_BY_TENANT_ID[${tenant_id}]}" != "${name}" ]]; then
        echo "ERROR: duplicate generated tenant id ${tenant_id} for ${name} and ${REPO_BY_TENANT_ID[${tenant_id}]}" >&2
        exit 1
    fi

    REF_KIND_BY_REPO["${name}"]="${ref_kind}"
    REF_VALUE_BY_REPO["${name}"]="${ref_value}"
    SOURCE_ORG_BY_REPO["${name}"]="${source_org}"
    SOURCE_NAME_BY_REPO["${name}"]="${source_name}"
    MANIFEST_PATH_BY_REPO["${name}"]="${manifest_path}"
    ORG_PREFIX_BY_REPO["${name}"]="${org_prefix}"
    DATABASE_ID_BY_REPO["${name}"]="${database_id}"
    TENANT_ID_BY_REPO["${name}"]="${tenant_id}"
    REPO_BY_TENANT_ID["${tenant_id}"]="${name}"
    deploy_repos+=("${name}")
}

discover_from_env() {
    local raw="${DEPLOY_REPOS:-}"
    local item
    local branch
    local source_org
    local source_name
    local manifest_path

    raw="${raw//,/ }"
    for item in ${raw}; do
        if is_discovery_tombstoned "${item}"; then
            echo "Skipping tombstoned deploy repo: ${item}" >&2
            continue
        fi

        branch="${DEPLOY_REPO_BRANCH_OVERRIDES[${item}]:-main}"
        source_org="${DEPLOY_REPO_SOURCE_ORG_OVERRIDES[${item}]:-${ORG}}"
        source_name="${DEPLOY_REPO_SOURCE_NAME_OVERRIDES[${item}]:-${item}}"
        manifest_path="${DEPLOY_REPO_MANIFEST_PATH_OVERRIDES[${item}]:-${MANIFEST_PATH}}"
        add_repo "${item}" "${branch}" "${source_org}" "${source_name}" "${manifest_path}" "" "convention"
    done
}

manifest_exists() {
    local source_org="$1"
    local source_name="$2"
    local branch="$3"
    local manifest_path="$4"

    gh api \
        "repos/${source_org}/${source_name}/contents/${manifest_path}/kustomization.yaml?ref=${branch}" \
        --jq '.type' >/dev/null 2>&1
}

discover_from_github() {
    if ! command -v gh >/dev/null 2>&1; then
        echo "ERROR: gh is required unless DEPLOY_REPOS is set" >&2
        exit 1
    fi

    local repo_list
    local enumerated_count
    local name
    local branch
    local is_private
    local is_archived
    repo_list="$(mktemp)"
    if ! gh repo list "${ORG}" \
        --limit "${LIMIT}" \
        --json name,defaultBranchRef,isPrivate,isArchived \
        --jq '.[] | [.name, (.defaultBranchRef.name // "main"), (.isPrivate|tostring), (.isArchived|tostring)] | @tsv' \
        > "${repo_list}"; then
        rm -f "${repo_list}"
        echo "ERROR: 'gh repo list ${ORG}' failed; refusing to proceed with empty discovery" >&2
        exit 1
    fi
    enumerated_count="$(grep -c . "${repo_list}" || true)"
    echo "Discovery: enumerated ${enumerated_count} repositories under ${ORG}" >&2

    while IFS=$'\t' read -r name branch is_private is_archived; do
        [[ -n "${name}" ]] || continue
        if ! [[ "${name}" =~ ${NAME_RE} ]]; then
            continue
        fi
        if is_discovery_tombstoned "${name}"; then
            echo "Skipping tombstoned deploy repo: ${name}" >&2
            continue
        fi
        if [[ "${is_archived}" == "true" ]]; then
            echo "Skipping archived deploy repo: ${name}" >&2
            continue
        fi
        if [[ "${is_private}" == "true" && "${INCLUDE_PRIVATE}" != "true" ]]; then
            echo "Skipping private deploy repo without private-source support: ${name}" >&2
            continue
        fi
        if ! manifest_exists "${ORG}" "${name}" "${branch:-main}" "${MANIFEST_PATH}"; then
            echo "Skipping deploy repo without ${MANIFEST_PATH}/kustomization.yaml: ${name}" >&2
            continue
        fi
        add_repo "${name}" "${branch:-main}" "${ORG}" "${name}" "${MANIFEST_PATH}" "" "convention"
    done < "${repo_list}"
    rm -f "${repo_list}"
}

add_explicit_repos() {
    local name
    local branch
    local source_org
    local source_name
    local manifest_path

    for name in "${EXPLICIT_DEPLOY_TENANTS[@]}"; do
        if is_discovery_tombstoned "${name}"; then
            echo "Skipping tombstoned explicit deploy repo: ${name}" >&2
            continue
        fi

        branch="${DEPLOY_REPO_BRANCH_OVERRIDES[${name}]:-main}"
        source_org="${DEPLOY_REPO_SOURCE_ORG_OVERRIDES[${name}]:-${ORG}}"
        source_name="${DEPLOY_REPO_SOURCE_NAME_OVERRIDES[${name}]:-${name}}"
        manifest_path="${DEPLOY_REPO_MANIFEST_PATH_OVERRIDES[${name}]:-${MANIFEST_PATH}}"

        add_repo \
            "${name}" \
            "${branch}" \
            "${source_org}" \
            "${source_name}" \
            "${manifest_path}" \
            "" \
            "explicit"
    done
}

render_optional_patches() {
    local name="$1"
    local source_name="${SOURCE_NAME_BY_REPO[${name}]}"
    local source_org="${SOURCE_ORG_BY_REPO[${name}]}"
    local database_id="${DATABASE_ID_BY_REPO[${name}]}"
    local ref_kind="${REF_KIND_BY_REPO[${name}]}"
    local ref_value="${REF_VALUE_BY_REPO[${name}]}"
    local manifest_path="${MANIFEST_PATH_BY_REPO[${name}]}"

    cat <<EOF
patches:
  - target:
      kind: Namespace
    patch: |-
      - op: add
        path: /metadata/labels/nwarila.io~1deploy-repo
        value: "${source_name}"
      - op: add
        path: /metadata/labels/nwarila.io~1repo-id
        value: "${database_id}"
      - op: add
        path: /metadata/labels/nwarila.io~1org
        value: "${source_org}"
EOF

    if [[ "${ref_kind}" == "branch" && "${ref_value}" == "main" ]]; then
        :
    elif [[ "${ref_kind}" == "branch" ]]; then
        cat <<EOF
  - target:
      kind: GitRepository
    patch: |-
      - op: replace
        path: /spec/ref/branch
        value: "${ref_value}"
EOF
    else
        cat <<EOF
  - target:
      kind: GitRepository
    patch: |-
      - op: remove
        path: /spec/ref/branch
      - op: add
        path: /spec/ref/${ref_kind}
        value: "${ref_value}"
EOF
    fi

    if [[ "${manifest_path}" != "${MANIFEST_PATH}" ]]; then
        cat <<EOF
  - target:
      kind: Kustomization
    patch: |-
      - op: replace
        path: /spec/path
        value: "./${manifest_path#./}"
EOF
    fi
}

render_overlay() {
    local name="$1"
    local tenant_id="${TENANT_ID_BY_REPO[${name}]}"
    local org_prefix="${ORG_PREFIX_BY_REPO[${name}]}"
    local source_org="${SOURCE_ORG_BY_REPO[${name}]}"
    local source_name="${SOURCE_NAME_BY_REPO[${name}]}"
    local database_id="${DATABASE_ID_BY_REPO[${name}]}"
    local app_auth_secret="${tenant_id}-gitops-source-auth"
    local tenant_dir="${TENANTS_DIR}/${tenant_id}"

    mkdir -p "${tenant_dir}"
    cat > "${tenant_dir}/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${tenant_id}
resources:
  - ../_template/zero-touch/base
configMapGenerator:
  - name: tenant-contract
    literals:
      - tenantId=${tenant_id}
      - orgPrefix=${org_prefix}
      - org=${source_org}
      - deployRepo=${source_name}
      - deployRepoGit=${source_name}.git
      - sourceName=${source_name}
      - appAuthSecret=${app_auth_secret}
      - repoId=${database_id}
generatorOptions:
  disableNameSuffixHash: true
  annotations:
    config.kubernetes.io/local-config: "true"
$(render_optional_patches "${name}")
replacements:
  - source:
      kind: ConfigMap
      name: tenant-contract
      fieldPath: data.tenantId
    targets:
      - select:
          kind: Kustomization
        fieldPaths:
          - metadata.name
          - spec.targetNamespace
  - source:
      kind: ConfigMap
      name: tenant-contract
      fieldPath: data.sourceName
    targets:
      - select:
          kind: GitRepository
          name: source-placeholder
        fieldPaths:
          - metadata.name
      - select:
          kind: Kustomization
        fieldPaths:
          - spec.sourceRef.name
  - source:
      kind: ConfigMap
      name: tenant-contract
      fieldPath: data.org
    targets:
      - select:
          kind: GitRepository
        fieldPaths:
          - spec.url
        options:
          delimiter: /
          index: 3
  - source:
      kind: ConfigMap
      name: tenant-contract
      fieldPath: data.deployRepoGit
    targets:
      - select:
          kind: GitRepository
        fieldPaths:
          - spec.url
        options:
          delimiter: /
          index: 4
  - source:
      kind: ConfigMap
      name: tenant-contract
      fieldPath: data.appAuthSecret
    targets:
      - select:
          kind: GitRepository
        fieldPaths:
          - spec.secretRef.name
      - select:
          kind: VaultStaticSecret
          name: app-auth-placeholder
        fieldPaths:
          - metadata.name
          - spec.destination.name
  - source:
      kind: ConfigMap
      name: tenant-contract
      fieldPath: data.orgPrefix
    targets:
      - select:
          kind: ServiceAccount
          name: vso-org-pull-placeholder
        fieldPaths:
          - metadata.name
        options:
          delimiter: '-'
          index: 3
      - select:
          kind: VaultStaticSecret
        fieldPaths:
          - spec.path
        options:
          delimiter: '/'
          index: 2
      - select:
          kind: VaultStaticSecret
        fieldPaths:
          - spec.vaultAuthRef
        options:
          delimiter: '-'
          # vaultAuthRef slash-collapse: operator/org is one segment; placeholder is index 4, not 2.
          index: 4
EOF
}

read_kustomization_resources() {
    local path="$1"

    awk '
        $0 ~ /^resources:[[:space:]]*$/ {
            in_resources = 1
            next
        }
        in_resources && $0 ~ /^[[:space:]]*-[[:space:]]+/ {
            entry = $0
            sub(/^[[:space:]]*-[[:space:]]*/, "", entry)
            sub(/[[:space:]]+#.*$/, "", entry)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", entry)
            if (entry != "") {
                print entry
            }
            next
        }
        in_resources && $0 !~ /^[[:space:]]*($|#)/ {
            in_resources = 0
        }
    ' "${path}"
}

update_tenants_kustomization() {
    local path="$1"
    local header="$2"
    shift 2
    local entries=("$@")
    local current_entries=()
    local output_entries=()
    local inserted_managed=false
    local entry
    local desired_entry
    local managed
    local tmp
    tmp="$(mktemp)"

    mapfile -t current_entries < <(read_kustomization_resources "${path}")
    for entry in "${current_entries[@]}"; do
        managed=false
        if is_managed_tenant_entry "${entry}"; then
            managed=true
        else
            for desired_entry in "${entries[@]}"; do
                if [[ "${entry}" == "${desired_entry}" ]]; then
                    managed=true
                    break
                fi
            done
        fi

        if [[ "${managed}" == "true" ]]; then
            if [[ "${inserted_managed}" == "false" ]]; then
                output_entries+=("${entries[@]}")
                inserted_managed=true
            fi
            continue
        fi
        output_entries+=("${entry}")
    done
    if [[ "${inserted_managed}" == "false" ]]; then
        output_entries+=("${entries[@]}")
    fi

    {
        printf '%s\n' "${header}"
        echo "apiVersion: kustomize.config.k8s.io/v1beta1"
        echo "kind: Kustomization"
        echo "resources:"
        for entry in "${output_entries[@]}"; do
            echo "  - ${entry}"
        done
    } > "${tmp}"

    mv "${tmp}" "${path}"
}

if [[ "${EXPLICIT_ONLY}" == "true" ]]; then
    :
elif [[ -n "${DEPLOY_REPOS:-}" ]]; then
    discover_from_env
else
    discover_from_github
fi

add_explicit_repos

if [[ "${#deploy_repos[@]}" -eq 0 && "${#DEPLOY_REPO_RETAINED_TENANTS[@]}" -eq 0 ]]; then
    echo "ERROR: no deploy repositories matched the contract" >&2
    exit 1
fi

if [[ "${#deploy_repos[@]}" -gt 0 ]]; then
    mapfile -t deploy_repos < <(printf '%s\n' "${deploy_repos[@]}" | sort -u)
fi

for tenant in "${DEPLOY_REPO_RETAINED_TENANTS[@]}"; do
    require_dir "${TENANTS_DIR}/${tenant}"
done

for repo in "${deploy_repos[@]}"; do
    render_overlay "${repo}"
done

tenant_entries=()
for repo in "${deploy_repos[@]}"; do
    tenant_entries+=("${TENANT_ID_BY_REPO[${repo}]}")
done
tenant_entries+=("${DEPLOY_REPO_RETAINED_TENANTS[@]}")
mapfile -t tenant_entries < <(printf '%s\n' "${tenant_entries[@]}" | sort -u)

update_tenants_kustomization \
    "${TENANTS_KUSTOMIZATION}" \
    "# Kustomize index for onboarded tenant security envelopes.
#
# Generated tenant entries are managed by scripts/sync-deploy-repos.sh." \
    "${tenant_entries[@]}"

if [[ "${#deploy_repos[@]}" -gt 0 ]]; then
    generated_tenant_ids=()
    for repo in "${deploy_repos[@]}"; do
        generated_tenant_ids+=("${TENANT_ID_BY_REPO[${repo}]}")
    done
    echo "Synchronized deploy tenants: ${generated_tenant_ids[*]}"
else
    echo "Synchronized deploy tenants: (none)"
fi
if [[ "${#DEPLOY_REPO_RETAINED_TENANTS[@]}" -gt 0 ]]; then
    echo "Retained deploy tenants: ${DEPLOY_REPO_RETAINED_TENANTS[*]}"
fi
