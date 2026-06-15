# Platform-critical deploy repository overrides.
#
# These inputs are consumed by scripts/sync-deploy-repos.sh. Normal deploy repos
# keep branch tracking. Repos listed here must use an immutable Flux ref because
# the cluster owns a platform trust decision for them.
#
# Explicit tenants are reviewed, non-convention sources that still use the same
# generated namespace, Flux source, Flux Kustomization, and tenant RBAC envelope.

PLATFORM_CRITICAL_DEPLOY_REPOS=()

# Vault workload ownership has been folded into the platform-owned apps/vault
# Kustomization. Keep deploy-vault tombstoned so convention discovery cannot
# recreate the retired app wrapper while the namespace envelope stays applied.
DEPLOY_REPO_DISCOVERY_TOMBSTONES=(
    deploy-vault
)

DEPLOY_REPO_RETAINED_TENANTS=(
    deploy-vault
)

EXPLICIT_DEPLOY_TENANTS=(
    herowars
)

DEPLOY_REPO_SOURCE_ORG_OVERRIDES["herowars"]="the-hero-wars-guys"
DEPLOY_REPO_SOURCE_NAME_OVERRIDES["herowars"]="deploy-herowars-engine-porter"
DEPLOY_REPO_URL_OVERRIDES["herowars"]="https://github.com/the-hero-wars-guys/deploy-herowars-engine-porter.git"
DEPLOY_REPO_PROVIDER_OVERRIDES["herowars"]="github"
DEPLOY_REPO_REF_KIND_OVERRIDES["herowars"]="branch"
DEPLOY_REPO_REF_OVERRIDES["herowars"]="main"
DEPLOY_REPO_SECRET_REF_OVERRIDES["herowars"]="herowars-gitops-source-auth"
