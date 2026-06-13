# Platform-critical deploy repository overrides.
#
# These inputs are consumed by scripts/sync-deploy-repos.sh. Normal deploy repos
# keep branch tracking. Repos listed here must use an immutable Flux ref because
# the cluster owns a platform trust decision for them.

PLATFORM_CRITICAL_DEPLOY_REPOS=(
    deploy-vault
)

DEPLOY_REPO_REF_KIND_OVERRIDES["deploy-vault"]="commit"
DEPLOY_REPO_REF_OVERRIDES["deploy-vault"]="bf7f0e0f9f5b6a66c2ae980fcd2f4d358bed9bd4"
