# Platform-critical deploy repository overrides.
#
# These inputs are consumed by scripts/sync-deploy-repos.sh. Normal deploy repos
# keep branch tracking. Repos listed here must use an immutable Flux ref because
# the cluster owns a platform trust decision for them.
#
# Explicit tenants are reviewed, non-convention sources that still use the same
# generated namespace, Flux source, Flux Kustomization, and tenant RBAC envelope.

PLATFORM_CRITICAL_DEPLOY_REPOS=(
    deploy-vault
)

DEPLOY_REPO_REF_KIND_OVERRIDES["deploy-vault"]="commit"
DEPLOY_REPO_REF_OVERRIDES["deploy-vault"]="bf7f0e0f9f5b6a66c2ae980fcd2f4d358bed9bd4"

EXPLICIT_DEPLOY_TENANTS=(
    herowars
)

DEPLOY_REPO_SOURCE_ORG_OVERRIDES["herowars"]="the-hero-wars-guys"
DEPLOY_REPO_SOURCE_NAME_OVERRIDES["herowars"]="ubi9-herowars-engine-porter"
DEPLOY_REPO_URL_OVERRIDES["herowars"]="ssh://git@github.com/the-hero-wars-guys/ubi9-herowars-engine-porter.git"
DEPLOY_REPO_REF_KIND_OVERRIDES["herowars"]="branch"
DEPLOY_REPO_REF_OVERRIDES["herowars"]="main"
DEPLOY_REPO_SECRET_REF_OVERRIDES["herowars"]="herowars-git-auth"
