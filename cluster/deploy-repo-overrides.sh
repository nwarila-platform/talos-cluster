# Platform-critical deploy repository overrides.
#
# These inputs are consumed by scripts/sync-deploy-repos.sh. Normal deploy repos
# keep branch tracking. Repos listed here must use an immutable Flux ref because
# the cluster owns a platform trust decision for them.
#
# Explicit tenants are reviewed, non-convention sources that still use the same
# generated zero-touch tenant overlay. Generated tenants are named:
#
#   <orgPrefix>-<repo-databaseId>
#
# orgPrefix must equal a provisioned org-pull VaultAuth at:
# clusters/talos-cluster/apps/vault-secrets-operator/org-pull/vaultauth-org-pull-<prefix>.yaml

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

EXPLICIT_DEPLOY_TENANTS=()

declare -A DEPLOY_REPO_ORG_PREFIX_OVERRIDES=()
declare -A DEPLOY_REPO_DATABASE_ID_OVERRIDES=()

EXPLICIT_DEPLOY_TENANTS+=(herowars)
DEPLOY_REPO_SOURCE_ORG_OVERRIDES["herowars"]="the-hero-wars-guys"
DEPLOY_REPO_SOURCE_NAME_OVERRIDES["herowars"]="deploy-herowars-engine-porter"
DEPLOY_REPO_REF_KIND_OVERRIDES["herowars"]="branch"
DEPLOY_REPO_REF_OVERRIDES["herowars"]="main"
DEPLOY_REPO_ORG_PREFIX_OVERRIDES["herowars"]="hwg"
DEPLOY_REPO_DATABASE_ID_OVERRIDES["herowars"]="1268831311"

# Convention-discovered repos also require explicit orgPrefix registration:
#
# DEPLOY_REPO_ORG_PREFIX_OVERRIDES["deploy-example"]="nwp"
# DEPLOY_REPO_DATABASE_ID_OVERRIDES["deploy-example"]="1202118418" # optional escape hatch; discovery normally supplies databaseId

# --- nwarila-platform (prefix nwp) ---------------------------------------------
# The orgPrefix registration is the deliberate TRUST GATE for convention discovery
# (ADR-0011): a repository must not be able to choose its own tenancy, namespace, or
# Vault path simply by picking a name. Discovery admits a repo only once a human has
# registered which organization it belongs to, which is why sync-deploy-repos.sh hard
# -errors on an unregistered prefix rather than guessing.
#
# ORDERING MATTERS: this registration must be MERGED BEFORE the repository publishes
# kubernetes/overlays/talos-cluster/. A repo that exposes the overlay while its prefix
# is unregistered makes the hourly sync exit 1 - which fails the whole run, not just
# that repo. See docs/runbooks/onboard-organization.md.
DEPLOY_REPO_ORG_PREFIX_OVERRIDES["deploy-platform-canary"]="nwp"
