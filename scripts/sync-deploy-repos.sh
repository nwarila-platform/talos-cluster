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

NAME_RE="^${PREFIX}[a-z0-9]([-a-z0-9]*[a-z0-9])?$"

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
deploy_repos=()

add_repo() {
    local name="$1"
    local branch="${2:-main}"

    if ! [[ "${name}" =~ ${NAME_RE} ]]; then
        echo "ERROR: deploy repo name does not match ${NAME_RE}: ${name}" >&2
        exit 1
    fi

    BRANCH_BY_REPO["${name}"]="${branch:-main}"
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

render_tenant() {
    local tenant="$1"
    local tenant_dir="${TENANTS_DIR}/${tenant}"

    mkdir -p "${tenant_dir}"
    render_template "${TENANT_TEMPLATE_DIR}/namespace.yaml.tmpl" "${tenant_dir}/namespace.yaml" "${tenant}"
    render_template "${TENANT_TEMPLATE_DIR}/networkpolicy-default-deny.yaml.tmpl" "${tenant_dir}/networkpolicy-default-deny.yaml" "${tenant}"
    render_template "${TENANT_TEMPLATE_DIR}/networkpolicy-allow-dns.yaml.tmpl" "${tenant_dir}/networkpolicy-allow-dns.yaml" "${tenant}"

    cat > "${tenant_dir}/flux-reconciler-rbac.yaml" <<EOF
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
      - secrets
      - serviceaccounts
      - services
    verbs: ["*"]
  - apiGroups: ["apps"]
    resources:
      - controllerrevisions
      - daemonsets
      - deployments
      - replicasets
      - statefulsets
    verbs: ["*"]
  - apiGroups: ["batch"]
    resources:
      - cronjobs
      - jobs
    verbs: ["*"]
  - apiGroups: ["networking.k8s.io"]
    resources:
      - ingresses
      - networkpolicies
    verbs: ["*"]
  - apiGroups: ["policy"]
    resources:
      - poddisruptionbudgets
    verbs: ["*"]
  - apiGroups: ["autoscaling"]
    resources:
      - horizontalpodautoscalers
    verbs: ["*"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources:
      - roles
      - rolebindings
    verbs: ["*"]
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

render_app() {
    local name="$1"
    local branch="$2"
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
    branch: ${branch}
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
    local tmp
    tmp="$(mktemp)"

    {
        printf '%s\n' "${header}"
        echo "apiVersion: kustomize.config.k8s.io/v1beta1"
        echo "kind: Kustomization"
        echo "resources:"
        for entry in "${entries[@]}"; do
            echo "  - ${entry}"
        done
    } > "${tmp}"

    mv "${tmp}" "${path}"
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
    render_app "${repo}" "${BRANCH_BY_REPO[${repo}]:-main}"
done

mapfile -t app_entries < <(
    {
        find "${APPS_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'
        printf '%s\n' "${deploy_repos[@]}"
    } | grep -Ev '^(_|$)' | sort -u
)
mapfile -t tenant_entries < <(
    {
        find "${TENANTS_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'
        printf '%s\n' "${deploy_repos[@]}"
    } | grep -Ev '^(_|$)' | sort -u
)

update_kustomization \
    "${APPS_KUSTOMIZATION}" \
    "# Kustomize index aggregating every app under this cluster.
# deploy-* entries are generated by scripts/sync-deploy-repos.sh." \
    "${app_entries[@]}"

update_kustomization \
    "${TENANTS_KUSTOMIZATION}" \
    "# Kustomize index for onboarded tenant security envelopes.
#
# deploy-* entries are generated by scripts/sync-deploy-repos.sh." \
    "${tenant_entries[@]}"

echo "Synchronized deploy repositories: ${deploy_repos[*]}"
