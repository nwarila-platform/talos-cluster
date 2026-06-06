# Platform-critical deploy repository overrides.
#
# These inputs are consumed by scripts/sync-deploy-repos.sh. Normal deploy repos
# keep branch tracking and the default tenant reconciler Role. Repos listed here
# must use an immutable Flux ref plus a tightened RBAC profile because the tenant
# namespace carries secret-zero or equivalent material.

PLATFORM_CRITICAL_DEPLOY_REPOS=(
    deploy-vault
)

DEPLOY_REPO_REF_KIND_OVERRIDES["deploy-vault"]="commit"
DEPLOY_REPO_REF_OVERRIDES["deploy-vault"]="81682df2a35ee309ccca828a180119fcaac03555"
DEPLOY_REPO_RBAC_PROFILE_OVERRIDES["deploy-vault"]="vault-secret-zero"
