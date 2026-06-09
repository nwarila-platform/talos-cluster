#!/usr/bin/env bash
# =============================================================================
# sync-deploy-repos.sh - Generate Flux wiring for deploy-* repositories.
#
# A repository is admitted only when all of these are true:
#   1. name matches deploy-*
#   2. repository is not archived
#   3. repository exposes kubernetes/overlays/talos-cluster/kustomization.yaml
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
COMMIT_RE="^[0-9a-f]{40}$"

declare -A DEPLOY_REPO_REF_KIND_OVERRIDES=()
declare -A DEPLOY_REPO_REF_OVERRIDES=()
declare -a PLATFORM_CRITICAL_DEPLOY_REPOS=()

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
deploy_repos=()

add_repo() {
    local name="$1"
    local branch="${2:-main}"
    local ref_kind="${DEPLOY_REPO_REF_KIND_OVERRIDES[${name}]:-branch}"
    local ref_value="${DEPLOY_REPO_REF_OVERRIDES[${name}]:-${branch:-main}}"

    if ! [[ "${name}" =~ ${NAME_RE} ]]; then
        echo "ERROR: deploy repo name does not match ${NAME_RE}: ${name}" >&2
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
    deploy_repos+=("${name}")
}

discover_from_env() {
    local raw="${DEPLOY_REPOS:-}"
    local item

    raw="${raw//,/ }"
    for item in ${raw}; do
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

    while IFS=$'\t' read -r name branch is_private is_archived; do
        [[ -n "${name}" ]] || continue
        if ! [[ "${name}" =~ ${NAME_RE} ]]; then
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
    done < <(
        gh repo list "${ORG}" \
            --limit "${LIMIT}" \
            --json name,defaultBranchRef,isPrivate,isArchived \
            --jq '.[] | [.name, (.defaultBranchRef.name // "main"), (.isPrivate|tostring), (.isArchived|tostring)] | @tsv'
    )
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

render_app() {
    local name="$1"
    local app_dir="${APPS_DIR}/${name}"

    mkdir -p "${app_dir}"

    cat > "${app_dir}/gitrepository.yaml" <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: ${name}
  namespace: ${name}
  labels:
    nwarila.io/deploy-repo: "true"
spec:
  interval: 5m
  ref:
$(render_git_ref "${name}")
  url: https://github.com/${ORG}/${name}.git
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
  path: ./${MANIFEST_PATH}
  prune: true
  wait: true
  timeout: 10m
  targetNamespace: ${name}
  serviceAccountName: deploy-reconciler
  sourceRef:
    kind: GitRepository
    name: ${name}
EOF

    cat > "${app_dir}/kustomization.yaml" <<EOF
# Generated by scripts/sync-deploy-repos.sh.
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - gitrepository.yaml
  - kustomization-flux.yaml
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
    local tmp
    tmp="$(mktemp)"

    mapfile -t current_entries < <(read_kustomization_resources "${path}")
    for entry in "${current_entries[@]}"; do
        if [[ "${entry}" =~ ${NAME_RE} ]]; then
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

if [[ "${#deploy_repos[@]}" -eq 0 ]]; then
    echo "ERROR: no deploy repositories matched the contract" >&2
    exit 1
fi

mapfile -t deploy_repos < <(printf '%s\n' "${deploy_repos[@]}" | sort -u)

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
    "${deploy_repos[@]}"

echo "Synchronized deploy repositories: ${deploy_repos[*]}"
