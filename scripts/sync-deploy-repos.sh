#!/usr/bin/env bash
# =============================================================================
# sync-deploy-repos.sh - Generate Flux wiring for deploy-* repositories.
#
# Convention-discovered repositories are admitted only when all of these are true:
#   1. name matches deploy-*
#   2. repository is not archived
#   3. repository exposes kubernetes/overlays/talos-cluster/kustomization.yaml
# Explicit tenants in cluster/deploy-repo-overrides.sh use the same renderer for
# reviewed cross-org or private sources that cannot be discovered by convention.
#
# By default, discovery uses the GitHub CLI. For deterministic local tests, set
# DEPLOY_REPOS to a comma or whitespace separated list of repository names.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ORG="${DEPLOY_REPO_ORG:-nwarila-platform}"
PREFIX="${DEPLOY_REPO_PREFIX:-deploy-}"
MANIFEST_PATH="${DEPLOY_REPO_PATH:-kubernetes/overlays/talos-cluster}"
LIMIT="${DEPLOY_REPO_LIMIT:-1000}"
INCLUDE_PRIVATE="${DEPLOY_REPO_INCLUDE_PRIVATE:-false}"

APPS_DIR="${DEPLOY_APPS_DIR:-${ROOT_DIR}/clusters/talos-cluster/apps}"
TENANTS_DIR="${DEPLOY_TENANTS_DIR:-${ROOT_DIR}/clusters/talos-cluster/tenants}"
TENANT_TEMPLATE_DIR="${DEPLOY_TENANT_TEMPLATE_DIR:-${TENANTS_DIR}/_template}"
APPS_KUSTOMIZATION="${DEPLOY_APPS_KUSTOMIZATION:-${APPS_DIR}/kustomization.yaml}"
TENANTS_KUSTOMIZATION="${DEPLOY_TENANTS_KUSTOMIZATION:-${TENANTS_DIR}/kustomization.yaml}"
OVERRIDES_FILE="${DEPLOY_REPO_OVERRIDES_FILE:-${ROOT_DIR}/cluster/deploy-repo-overrides.sh}"

NAME_RE="^${PREFIX}[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
TENANT_RE="^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
COMMIT_RE="^[0-9a-f]{40}$"

declare -a EXPLICIT_DEPLOY_TENANTS=()
declare -A DEPLOY_REPO_BRANCH_OVERRIDES=()
declare -A DEPLOY_REPO_SOURCE_ORG_OVERRIDES=()
declare -A DEPLOY_REPO_SOURCE_NAME_OVERRIDES=()
declare -A DEPLOY_REPO_URL_OVERRIDES=()
declare -A DEPLOY_REPO_MANIFEST_PATH_OVERRIDES=()
declare -A DEPLOY_REPO_PROVIDER_OVERRIDES=()
declare -A DEPLOY_REPO_SECRET_REF_OVERRIDES=()
declare -A DEPLOY_REPO_REF_KIND_OVERRIDES=()
declare -A DEPLOY_REPO_REF_OVERRIDES=()
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

for repo in "${PLATFORM_CRITICAL_DEPLOY_REPOS[@]}"; do
    if ! [[ "${repo}" =~ ${NAME_RE} ]]; then
        echo "ERROR: platform-critical deploy repo name does not match ${NAME_RE}: ${repo}" >&2
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
    if [[ "${ref_kind}" == "commit" && ! "${ref_value}" =~ ${COMMIT_RE} ]]; then
        echo "ERROR: platform-critical deploy repo ${repo} commit ref must be a 40-character SHA" >&2
        exit 1
    fi
done

for repo in "${DEPLOY_REPO_DISCOVERY_TOMBSTONES[@]}"; do
    if ! [[ "${repo}" =~ ${NAME_RE} ]]; then
        echo "ERROR: deploy repo discovery tombstone does not match ${NAME_RE}: ${repo}" >&2
        exit 1
    fi
done

for tenant in "${DEPLOY_REPO_RETAINED_TENANTS[@]}"; do
    if ! [[ "${tenant}" =~ ${NAME_RE} ]]; then
        echo "ERROR: retained deploy tenant does not match ${NAME_RE}: ${tenant}" >&2
        exit 1
    fi
done

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

require_dir "${APPS_DIR}"
require_dir "${TENANTS_DIR}"
require_dir "${TENANT_TEMPLATE_DIR}"
require_file "${APPS_KUSTOMIZATION}"
require_file "${TENANTS_KUSTOMIZATION}"
require_file "${TENANT_TEMPLATE_DIR}/namespace.yaml.tmpl"
require_file "${TENANT_TEMPLATE_DIR}/networkpolicy-default-deny.yaml.tmpl"
require_file "${TENANT_TEMPLATE_DIR}/networkpolicy-allow-dns.yaml.tmpl"

if [[ "${INCLUDE_PRIVATE}" != "true" && "${INCLUDE_PRIVATE}" != "false" ]]; then
    echo "ERROR: DEPLOY_REPO_INCLUDE_PRIVATE must be true or false" >&2
    exit 1
fi

declare -A BRANCH_BY_REPO=()
declare -A REF_KIND_BY_REPO=()
declare -A REF_VALUE_BY_REPO=()
declare -A SOURCE_NAME_BY_REPO=()
declare -A SOURCE_URL_BY_REPO=()
declare -A MANIFEST_PATH_BY_REPO=()
declare -A PROVIDER_BY_REPO=()
declare -A SECRET_REF_BY_REPO=()
deploy_repos=()

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

is_discovery_tombstoned() {
    local name="$1"

    array_contains "${name}" "${DEPLOY_REPO_DISCOVERY_TOMBSTONES[@]}"
}

generated_paths_are_trackable() {
    local name="$1"
    local app_path="clusters/talos-cluster/apps/${name}/kustomization.yaml"
    local tenant_path="clusters/talos-cluster/tenants/${name}/kustomization.yaml"

    if ! git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        return 0
    fi

    if git -C "${ROOT_DIR}" check-ignore -q -- "${app_path}"; then
        return 1
    fi
    if git -C "${ROOT_DIR}" check-ignore -q -- "${tenant_path}"; then
        return 1
    fi
    return 0
}

add_repo() {
    local name="$1"
    local branch="${2:-main}"
    local source_org="${3:-${ORG}}"
    local source_name="${4:-${name}}"
    local manifest_path="${5:-${MANIFEST_PATH}}"
    local source_url="${6:-}"
    local provider="${7:-}"
    local secret_ref="${8:-}"
    local admission_mode="${9:-convention}"
    local ref_kind="${DEPLOY_REPO_REF_KIND_OVERRIDES[${name}]:-branch}"
    local ref_value="${DEPLOY_REPO_REF_OVERRIDES[${name}]:-${branch:-main}}"

    if [[ "${admission_mode}" == "convention" ]] && ! [[ "${name}" =~ ${NAME_RE} ]]; then
        echo "ERROR: deploy repo name does not match ${NAME_RE}: ${name}" >&2
        exit 1
    fi
    if [[ "${admission_mode}" == "explicit" ]] && ! [[ "${name}" =~ ${TENANT_RE} ]]; then
        echo "ERROR: explicit tenant name does not match ${TENANT_RE}: ${name}" >&2
        exit 1
    fi
    if [[ "${ref_kind}" != "branch" && "${ref_kind}" != "tag" && "${ref_kind}" != "commit" ]]; then
        echo "ERROR: unsupported GitRepository ref kind for ${name}: ${ref_kind}" >&2
        exit 1
    fi
    if [[ "${ref_kind}" == "commit" && ! "${ref_value}" =~ ${COMMIT_RE} ]]; then
        echo "ERROR: commit ref for ${name} must be a 40-character SHA: ${ref_value}" >&2
        exit 1
    fi

    BRANCH_BY_REPO["${name}"]="${branch:-main}"
    REF_KIND_BY_REPO["${name}"]="${ref_kind}"
    REF_VALUE_BY_REPO["${name}"]="${ref_value}"
    SOURCE_NAME_BY_REPO["${name}"]="${source_name}"
    SOURCE_URL_BY_REPO["${name}"]="${source_url:-https://github.com/${source_org}/${source_name}.git}"
    MANIFEST_PATH_BY_REPO["${name}"]="${manifest_path}"
    PROVIDER_BY_REPO["${name}"]="${provider}"
    SECRET_REF_BY_REPO["${name}"]="${secret_ref}"
    deploy_repos+=("${name}")
}

discover_from_env() {
    local raw="${DEPLOY_REPOS:-}"
    local item

    raw="${raw//,/ }"
    for item in ${raw}; do
        if is_discovery_tombstoned "${item}"; then
            echo "Skipping tombstoned deploy repo: ${item}" >&2
            continue
        fi
        add_repo "${item}" "main"
    done
}

manifest_exists() {
    local name="$1"
    local branch="$2"
    gh api \
        "repos/${ORG}/${name}/contents/${MANIFEST_PATH}/kustomization.yaml?ref=${branch}" \
        --jq '.type' >/dev/null 2>&1
}

discover_from_github() {
    if ! command -v gh >/dev/null 2>&1; then
        echo "ERROR: gh is required unless DEPLOY_REPOS is set" >&2
        exit 1
    fi

    local repo_list
    local enumerated_count
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
        if ! manifest_exists "${name}" "${branch:-main}"; then
            echo "Skipping deploy repo without ${MANIFEST_PATH}/kustomization.yaml: ${name}" >&2
            continue
        fi
        add_repo "${name}" "${branch:-main}"
    done < "${repo_list}"
    rm -f "${repo_list}"
}

add_explicit_repos() {
    local name
    local branch
    local source_org
    local source_name
    local manifest_path
    local source_url
    local provider
    local secret_ref

    for name in "${EXPLICIT_DEPLOY_TENANTS[@]}"; do
        if is_discovery_tombstoned "${name}"; then
            echo "Skipping tombstoned explicit deploy repo: ${name}" >&2
            continue
        fi
        if ! generated_paths_are_trackable "${name}"; then
            echo "Skipping explicit deploy repo with ignored generated paths: ${name}" >&2
            continue
        fi

        branch="${DEPLOY_REPO_BRANCH_OVERRIDES[${name}]:-main}"
        source_org="${DEPLOY_REPO_SOURCE_ORG_OVERRIDES[${name}]:-${ORG}}"
        source_name="${DEPLOY_REPO_SOURCE_NAME_OVERRIDES[${name}]:-${name}}"
        manifest_path="${DEPLOY_REPO_MANIFEST_PATH_OVERRIDES[${name}]:-${MANIFEST_PATH}}"
        source_url="${DEPLOY_REPO_URL_OVERRIDES[${name}]:-}"
        provider="${DEPLOY_REPO_PROVIDER_OVERRIDES[${name}]:-}"
        secret_ref="${DEPLOY_REPO_SECRET_REF_OVERRIDES[${name}]:-}"

        add_repo \
            "${name}" \
            "${branch}" \
            "${source_org}" \
            "${source_name}" \
            "${manifest_path}" \
            "${source_url}" \
            "${provider}" \
            "${secret_ref}" \
            "explicit"
    done
}

render_template() {
    local source="$1"
    local target="$2"
    local tenant="$3"

    sed "s/__TENANT_NAMESPACE__/${tenant}/g" "${source}" > "${target}"
}

render_reconciler_rbac_default() {
    local tenant="$1"
    local target="$2"

    cat > "${target}" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deploy-reconciler
  namespace: ${tenant}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deploy-reconciler
  namespace: ${tenant}
rules:
  - apiGroups: [""]
    resources:
      - configmaps
      - endpoints
      - events
      - persistentvolumeclaims
      - pods
      - pods/log
      - serviceaccounts
      - services
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apps"]
    resources:
      - controllerrevisions
      - daemonsets
      - deployments
      - replicasets
      - statefulsets
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["batch"]
    resources:
      - cronjobs
      - jobs
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources:
      - ingresses
      - networkpolicies
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["cilium.io"]
    resources:
      - ciliumnetworkpolicies
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["policy"]
    resources:
      - poddisruptionbudgets
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["autoscaling"]
    resources:
      - horizontalpodautoscalers
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deploy-reconciler
  namespace: ${tenant}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: deploy-reconciler
subjects:
  - kind: ServiceAccount
    name: deploy-reconciler
    namespace: ${tenant}
EOF
}

render_reconciler_rbac() {
    local tenant="$1"
    local target="$2"

    render_reconciler_rbac_default "${tenant}" "${target}"
}

render_tenant() {
    local tenant="$1"
    local tenant_dir="${TENANTS_DIR}/${tenant}"

    mkdir -p "${tenant_dir}"
    render_template "${TENANT_TEMPLATE_DIR}/namespace.yaml.tmpl" "${tenant_dir}/namespace.yaml" "${tenant}"
    render_template "${TENANT_TEMPLATE_DIR}/networkpolicy-default-deny.yaml.tmpl" "${tenant_dir}/networkpolicy-default-deny.yaml" "${tenant}"
    render_template "${TENANT_TEMPLATE_DIR}/networkpolicy-allow-dns.yaml.tmpl" "${tenant_dir}/networkpolicy-allow-dns.yaml" "${tenant}"
    render_reconciler_rbac "${tenant}" "${tenant_dir}/flux-reconciler-rbac.yaml"

    cat > "${tenant_dir}/kustomization.yaml" <<EOF
# Generated by scripts/sync-deploy-repos.sh.
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - namespace.yaml
  - networkpolicy-default-deny.yaml
  - networkpolicy-allow-dns.yaml
  - flux-reconciler-rbac.yaml
EOF
}

render_git_ref() {
    local name="$1"
    local ref_kind="${REF_KIND_BY_REPO[${name}]:-branch}"
    local ref_value="${REF_VALUE_BY_REPO[${name}]:-${BRANCH_BY_REPO[${name}]:-main}}"

    printf '    %s: %s\n' "${ref_kind}" "${ref_value}"
}

render_provider_field() {
    local name="$1"
    local provider="${PROVIDER_BY_REPO[${name}]:-}"

    if [[ -n "${provider}" ]]; then
        printf '  provider: %s\n' "${provider}"
    fi
}

render_source_fields() {
    local name="$1"
    local source_url="${SOURCE_URL_BY_REPO[${name}]:-https://github.com/${ORG}/${name}.git}"
    local secret_ref="${SECRET_REF_BY_REPO[${name}]:-}"

    if [[ -n "${secret_ref}" ]]; then
        printf '  secretRef:\n'
        printf '    name: %s\n' "${secret_ref}"
    fi
    printf '  url: %s\n' "${source_url}"
}

render_gitrepository_spec() {
    local name="$1"

    printf '  interval: 5m\n'
    render_provider_field "${name}"
    printf '  ref:\n'
    render_git_ref "${name}"
    render_source_fields "${name}"
}

render_app_resources() {
    local name="$1"
    local secret_ref="${SECRET_REF_BY_REPO[${name}]:-}"

    if [[ -n "${secret_ref}" ]]; then
        printf '  - %s.sops.yaml\n' "${secret_ref}"
    fi
    printf '  - gitrepository.yaml\n'
    printf '  - kustomization-flux.yaml\n'
}

render_app() {
    local name="$1"
    local app_dir="${APPS_DIR}/${name}"
    local source_name="${SOURCE_NAME_BY_REPO[${name}]:-${name}}"
    local manifest_path="${MANIFEST_PATH_BY_REPO[${name}]:-${MANIFEST_PATH}}"

    mkdir -p "${app_dir}"

    cat > "${app_dir}/gitrepository.yaml" <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: ${source_name}
  namespace: ${name}
  labels:
    nwarila.io/deploy-repo: "true"
spec:
$(render_gitrepository_spec "${name}")
EOF

    cat > "${app_dir}/kustomization-flux.yaml" <<EOF
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: ${name}
  namespace: ${name}
  labels:
    nwarila.io/deploy-repo: "true"
spec:
  interval: 10m
  path: ./${manifest_path}
  prune: true
  wait: true
  timeout: 10m
  targetNamespace: ${name}
  serviceAccountName: deploy-reconciler
  sourceRef:
    kind: GitRepository
    name: ${source_name}
EOF

    cat > "${app_dir}/kustomization.yaml" <<EOF
# Generated by scripts/sync-deploy-repos.sh.
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
$(render_app_resources "${name}")
EOF
}

update_kustomization() {
    local path="$1"
    local header="$2"
    shift 2
    local entries=("$@")
    local current_entries=()
    local output_entries=()
    local inserted_managed=false
    local entry
    local managed
    local managed_entry
    local tmp
    tmp="$(mktemp)"

    mapfile -t current_entries < <(read_kustomization_resources "${path}")
    for entry in "${current_entries[@]}"; do
        managed=false
        if [[ "${entry}" =~ ${NAME_RE} ]]; then
            managed=true
        else
            for managed_entry in "${entries[@]}"; do
                if [[ "${entry}" == "${managed_entry}" ]]; then
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

if [[ -n "${DEPLOY_REPOS:-}" ]]; then
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

tenant_entries=("${deploy_repos[@]}" "${DEPLOY_REPO_RETAINED_TENANTS[@]}")
mapfile -t tenant_entries < <(printf '%s\n' "${tenant_entries[@]}" | sort -u)

for repo in "${deploy_repos[@]}"; do
    render_tenant "${repo}"
    render_app "${repo}"
done

update_kustomization \
    "${APPS_KUSTOMIZATION}" \
    "# Kustomize index aggregating every app under this cluster.
# deploy-* entries are generated by scripts/sync-deploy-repos.sh." \
    "${deploy_repos[@]}"

update_kustomization \
    "${TENANTS_KUSTOMIZATION}" \
    "# Kustomize index for onboarded tenant security envelopes.
#
# deploy-* entries are generated by scripts/sync-deploy-repos.sh." \
    "${tenant_entries[@]}"

if [[ "${#deploy_repos[@]}" -gt 0 ]]; then
    echo "Synchronized deploy repositories: ${deploy_repos[*]}"
else
    echo "Synchronized deploy repositories: (none)"
fi
if [[ "${#DEPLOY_REPO_RETAINED_TENANTS[@]}" -gt 0 ]]; then
    echo "Retained deploy tenants: ${DEPLOY_REPO_RETAINED_TENANTS[*]}"
fi
