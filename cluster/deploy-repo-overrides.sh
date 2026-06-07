# Platform-critical deploy repository overrides.
#
# These inputs are consumed by scripts/sync-deploy-repos.sh. Normal deploy repos
# keep branch tracking. Repos listed here must use an immutable Flux ref because
# the cluster owns a platform trust decision for them.

PLATFORM_CRITICAL_DEPLOY_REPOS=(
    deploy-vault
)

DEPLOY_REPO_REF_KIND_OVERRIDES["deploy-vault"]="commit"
DEPLOY_REPO_REF_OVERRIDES["deploy-vault"]="eee300147c949445da37da0c0fd34f33c85fc01a"
