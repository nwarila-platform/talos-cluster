# ADR-0011: Auto-Discover Deploy Repositories by Convention

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-01                              |
| Authors        | Nick Warila (@NWarila), Codex           |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0008, ADR-0010, local Flux manifests |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

`deploy-*` repositories under `nwarila-platform` are the app deployment surface.
When a repo matches the naming convention and exposes
`kubernetes/overlays/talos-cluster/kustomization.yaml`, talos-cluster
automation generates the namespace security envelope plus tenant-scoped Flux
`GitRepository` and `Kustomization` resources. After that, normal workload and
image changes happen in the `deploy-*` repo, not in `talos-cluster`.

## Context and Problem Statement

ADR-0008 makes `talos-cluster` the Flux source of truth for the cluster. That is
correct for cluster machinery, but it becomes friction if every new workload
requires a bespoke talos PR. The operator goal is: "we can deploy whatever
systems we want as long as it matches the deploy-* format, it auto deploys with
no additional work."

Flux does not currently have an in-repo wildcard source that says "reconcile
every GitHub repository matching this prefix." The cluster therefore needs one
generic generation layer that turns the repo convention into explicit Flux CRs.
The generation layer must be safe enough that a repo name alone does not grant
cluster-admin deployment power.

## Decision Drivers

1. **No hand-maintained app wiring.** Adding a new deploy repo should not require
   editing `clusters/talos-cluster/apps/kustomization.yaml`,
   `clusters/talos-cluster/tenants/kustomization.yaml`, or `.gitignore`.
2. **Clear contract.** A repo must prove intent by both name and manifest path.
3. **Tenant isolation.** App repos must reconcile through namespace-scoped Flux
   ServiceAccounts, not the controller's cluster-admin identity.
4. **GitOps auditability.** Generated resources still land in git before Flux
   applies them, preserving the source-of-truth trail.
5. **No accidental exposure.** Tenant envelopes default to restricted Pod
   Security, default-deny NetworkPolicy, and DNS egress only. App-specific
   ingress belongs in the app repo.

## Considered Options

1. **Manual talos PR per deploy repo.**
2. **Scheduled GitHub Actions sync that generates PRs.**
3. **Scheduled sync that writes directly to `main`.**
4. **In-cluster custom controller that discovers GitHub repositories.**
5. **Switch back to an ArgoCD ApplicationSet-style SCM generator.**

## Decision Outcome

Chosen option: **Option 2, scheduled GitHub Actions sync that generates PRs.**

The sync script discovers repositories under `nwarila-platform` that:

- match `^deploy-[a-z0-9]([-a-z0-9]*[a-z0-9])?$`;
- are not archived;
- are public/readable to the workflow;
- expose `kubernetes/overlays/talos-cluster/kustomization.yaml`.

For each admitted repo, the script generates:

- `clusters/talos-cluster/tenants/<repo>/`: Namespace, default-deny
  NetworkPolicy, DNS egress NetworkPolicy, and a namespace-scoped
  `deploy-reconciler` ServiceAccount/Role/RoleBinding;
- `clusters/talos-cluster/apps/<repo>/`: colocated Flux `GitRepository` and
  `Kustomization` resources in the tenant namespace, with
  `serviceAccountName: deploy-reconciler`;
- sorted app and tenant Kustomize indexes.

The generated Flux source and Kustomization live in the tenant namespace to
respect the cluster's `--no-cross-namespace-refs=true` Flux hardening. The
Kustomization uses `targetNamespace: <repo>` so namespaced workload objects land
in the tenant namespace even if the app repo omits `metadata.namespace`.

Reviewed exceptions can be listed as explicit tenants in
`cluster/deploy-repo-overrides.sh` when a tenant source cannot be discovered by
the `deploy-*`/`nwarila-platform` convention, for example a private cross-org
repository. These entries use the same generated namespace, Flux
`GitRepository`, Flux `Kustomization`, and tenant RBAC envelope. They remain
branch-tracking unless the override file explicitly assigns an immutable ref,
and private sources must reference a namespace-local Flux source-auth Secret
without committing credential material.

Every generated tenant gets the same namespace-scoped `deploy-reconciler` Role.
That default Role covers normal namespaced workload resources, but deliberately
excludes core `secrets` and tenant-authored `roles`/`rolebindings`. SOPS
material is delivered only by the hand-owned platform tree reconciled by
`flux-system`, not by tenant deploy repos, and tenant-managed RBAC would be a
privilege-escalation path rather than ordinary app configuration.

Platform-critical deploy repos are a deliberate exception only to the normal
branch-tracking model. When a tenant namespace carries secret-zero or equivalent
material, `scripts/sync-deploy-repos.sh` reads
`cluster/deploy-repo-overrides.sh` and renders that tenant with an immutable
Flux `GitRepository.spec.ref` (`commit` or `tag`) instead of the discovered
default branch.

`deploy-vault` uses this exception because the namespace contains the
SOPS-delivered `vault-ra-cert` IAM Roles Anywhere certificate/key used by Vault
KMS auto-unseal. Pinning deploy-vault to a reviewed commit makes workload
changes require a talos-cluster ref-bump PR before Flux applies them. The
default Role's removal of `secrets`, `roles`, and `rolebindings` is universal
defense-in-depth, not a Vault-specific exception. RBAC alone is not the primary
control: a permitted workload update could still mount an existing namespace
Secret. The immutable ref is therefore the load-bearing review gate for this
secret-zero boundary.

Direct scheduled writes to `main` are intentionally not enabled in this ADR.
They can be added only by a superseding or implementing decision that explicitly
accepts the future-change-authority risk and confirms branch protection allows
the bot to bypass review.

## Pros and Cons of the Options

### Option 1: Manual talos PR per deploy repo

- **Good, because** every new app has explicit cluster review.
- **Bad, because** it violates the operator goal and turns app deployment into a
  talos-maintenance task.

### Option 2: Scheduled generated PRs (chosen)

- **Good, because** humans and agents do not hand-author per-app Flux wiring.
- **Good, because** generated changes remain reviewable and auditable.
- **Good, because** branch protection and validation still gate cluster source
  changes.
- **Bad, because** the final merge is still a control-plane change unless an
  approved auto-merge/direct-push policy is added later.

### Option 3: Scheduled direct writes to `main`

- **Good, because** it most closely matches "no additional work."
- **Bad, because** it gives scheduled automation persistent authority to change
  the cluster source of truth. That needs explicit approval and branch-protection
  design before it is safe.

### Option 4: In-cluster custom controller

- **Good, because** it could discover repos without committing generated files.
- **Bad, because** it adds a bespoke controller, GitHub credentials in-cluster,
  and a larger attack/debug surface for a problem a deterministic generator can
  solve.

### Option 5: ArgoCD ApplicationSet-style SCM generator

- **Good, because** SCM provider generators are a known pattern for this.
- **Bad, because** this cluster has already adopted Flux as the GitOps engine.
  Reintroducing ArgoCD would split the control plane.

## Confirmation

This decision is confirmed when:

1. `scripts/sync-deploy-repos.sh` admits `deploy-vault` and skips deploy repos
   that are archived, private without configured support, or missing the Talos
   overlay.
2. `kubectl kustomize clusters/talos-cluster` renders after generated resources
   are present.
3. Flux reconciles the generated tenant `GitRepository` and `Kustomization`.
4. A future workload/image change in `deploy-vault` deploys by changing only the
   `deploy-vault` repository.

## Consequences

### Positive

- New app repos get a predictable, low-friction path into the cluster.
- App teams/repos own their manifests and image digests after onboarding.
- Tenant Flux reconciliation is namespace-scoped instead of cluster-admin.
- The deny-all `.gitignore` becomes pattern-based for `deploy-*` outputs.
- Every tenant reconciler excludes secret and tenant-RBAC escalation resources
  by default.
- Platform-critical tenants can force reviewed talos-cluster ref bumps before
  sensitive workload changes apply.

### Negative

- The sync workflow needs GitHub repo-listing visibility. Public repos work with
  the default token; private deploy repos need a deliberate credential strategy.
- Generated PRs still require merge unless a later auto-merge/direct-push policy
  is accepted.
- App repos that need cluster-scoped resources cannot use this path; those
  remain cluster-platform changes.
- Platform-critical pinned refs add an intentional talos-cluster maintenance
  step whenever those apps need to advance.

### Neutral

- The app repo remains responsible for its own Kustomize overlay, PSS-compliant
  pod specs, image pins, and app-specific NetworkPolicies.
- The sync skips repos that do not expose the expected overlay instead of
  creating partial Flux resources.
- Re-homing a secret-zero-bearing app to a hand-owned platform Kustomization, or
  replacing stored secret-zero with OIDC/SPIFFE federation, may still be
  stronger. Those are architectural migrations outside this ADR's deploy-repo
  discovery scope.

## Assumptions

1. `deploy-*` repositories are trusted nwarila-platform deployment repositories.
2. Public/readable deploy repos are sufficient for the first implementation.
3. Workloads should be namespaced. Cluster-scoped CRDs, ClusterRoles, admission
   policies, and storage/controller installs remain `talos-cluster` work.
4. The default `deploy-reconciler` Role covers namespaced workload kinds, but
   Secrets and tenant-authored RBAC remain outside the deploy-repo contract.
5. Platform-critical deploy repo tags are protected if used; otherwise pin by
   full commit SHA.

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

- The PR that adds `scripts/sync-deploy-repos.sh`,
  `.github/workflows/sync-deploy-repos.yaml`, and generated `deploy-vault`
  wiring implements the first pass.

## Related ADRs

- [ADR-0008](0008-gitops-via-flux.md) - Flux is the cluster GitOps engine.
- [ADR-0010](0010-adopt-kyverno-policy-engine.md) - Kyverno provides the
  policy substrate for deploy-repo guardrails and image verification.

## Compliance Notes

| Framework            | Control / Practice ID | Evidence Contribution |
| -------------------- | --------------------- | --------------------- |
| NIST SP 800-53 Rev. 5 | CM-2, CM-3            | Generated deploy wiring remains source-controlled and reviewable before Flux applies it. |
| NIST SP 800-190      | 4.1, 4.5              | Namespaced deployment and Kyverno image verification reduce workload supply-chain risk. |
| SSDF                 | PO.5, PS.3            | Defines a repeatable deployment intake contract and provenance-aware admission path. |
