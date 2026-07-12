# ADR-0017: Fold Vault into talos-cluster as a platform service

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-15                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0011, ADR-0012, ADR-0013, ADR-0015, imported Vault ADRs |
| Informed       | future platform operators, future deploy-* maintainers |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Vault is platform infrastructure, not a tenant workload. Fold it out of the
separate `deploy-vault` deploy repository and into this repository as a
first-class platform service at `clusters/talos-cluster/apps/vault/`, reconciled
by the platform-owned `flux-system/vault` Kustomization. Retain only the
`deploy-vault` namespace envelope under
`clusters/talos-cluster/tenants/deploy-vault/` so the namespace and baseline
NetworkPolicies remain independent from the prunable Vault workload tree.

## Context and Problem Statement

Vault is the cluster's secret-zero system. Before the fold, Vault was delivered
through the same auto-discovered, commit-pinned deploy-repository mechanism used
for tenant workloads: the separate `deploy-vault` repository supplied the
workload manifests, while this repository generated the tenant envelope and
Flux wiring.

That model was useful while Vault was being introduced, but it added an
unnecessary indirection layer for platform infrastructure. Treating Vault like a
tenant made ordinary platform review depend on a second repository and left the
most sensitive cluster service behind deploy-repo discovery and ref-bump
plumbing that ADR-0011 designed for application delivery.

The architectural question was whether Vault should continue to be delivered as
a platform-critical deploy repository or become a directly owned platform
service in `talos-cluster`.

## Decision Drivers

1. Keep Vault ownership in the cluster platform trust root.
2. Remove the deploy-repo delivery layer from the cluster's secret-zero system.
3. Preserve zero-disruption migration by adopting live resources before pruning
   retired Flux ownership.
4. Keep the `deploy-vault` namespace and baseline NetworkPolicies outside the
   prunable Vault workload tree.
5. Make future Vault changes visible as direct `talos-cluster` platform changes.
6. Prevent convention discovery from recreating the retired deploy-repo wrapper.

## Considered Options

1. Keep Vault as a commit-pinned `deploy-vault` deploy repository.
2. Fold Vault into `talos-cluster` as a platform-owned app while retaining the
   existing namespace envelope.
3. Move both the Vault workload and the `deploy-vault` namespace into a single
   platform app tree.
4. Replace Vault with a different secret-management service.

## Decision Outcome

Chosen option: **Option 2, fold Vault into `talos-cluster` as a platform-owned
app while retaining the existing namespace envelope**.

The accepted steady state is:

- Vault workload manifests live at `clusters/talos-cluster/apps/vault/`.
- The platform-owned Flux Kustomization `flux-system/vault` owns that workload.
- The separate `deploy-vault` deploy repository is retired.
- Deploy-repo discovery keeps `deploy-vault` tombstoned so convention discovery
  cannot recreate the retired app wrapper.
- The `deploy-vault` namespace, baseline NetworkPolicies, and reconciler RBAC
  remain under `clusters/talos-cluster/tenants/deploy-vault/` as the namespace
  envelope.

The namespace envelope is deliberately separate from the Vault workload. The
workload tree may be reconciled with pruning enabled, but the namespace must not
be pruned as part of a missed or malformed Vault workload render because that
could cascade-delete Vault PVCs.

The migration used adopt-before-prune sequencing: platform ownership adopted the
live Vault resources before retiring the generated deploy-repo wiring. That made
the fold a control-plane ownership change rather than a workload redeploy.

## Pros and Cons of the Options

### Option 1: Keep Vault as a commit-pinned deploy repository

- **Good, because** it kept the ADR-0011 platform-critical deploy-repo exception
  intact.
- **Bad, because** it continued to treat platform secret-zero infrastructure as
  tenant-shaped application delivery.
- **Bad, because** ordinary Vault platform changes still depended on a second
  repository and generated Flux wiring.

### Option 2: Fold Vault into `talos-cluster` and retain the namespace envelope

- **Good, because** Vault becomes a direct platform service owned by the cluster
  source of truth.
- **Good, because** the deploy-repo layer and ref-bump path are removed from the
  secret-zero system.
- **Good, because** retaining the namespace envelope protects Vault PVCs from an
  app-tree prune failure mode.
- **Bad, because** ADR-0011's `deploy-vault` worked example becomes historical
  and must be explicitly marked as superseded.

### Option 3: Move workload and namespace into one platform app tree

- **Good, because** it would make all Vault manifests colocated.
- **Bad, because** a pruned app render could delete the namespace and cascade to
  persistent Vault data.
- **Bad, because** it would erase the useful distinction between namespace
  envelope and workload ownership.

### Option 4: Replace Vault

- **Good, because** it could remove operational complexity if a simpler secret
  authority existed.
- **Bad, because** Vault already carries the accepted KMS auto-unseal, recovery,
  internal TLS, VSO, and backup design records.
- **Bad, because** replacement is outside the scope of the fold and would be a
  much larger secret-zero migration.

## Confirmation

This decision is confirmed when:

1. `clusters/talos-cluster/apps/deploy-vault/` is absent.
2. `clusters/talos-cluster/apps/vault/` is reconciled by the platform-owned
   `flux-system/vault` Kustomization.
3. `clusters/talos-cluster/tenants/deploy-vault/` contains only the namespace
   envelope and does not reintroduce `GitRepository`, `Kustomization`
   `sourceRef`, or deploy-repo delivery.
4. `cluster/deploy-repo-overrides.sh` keeps `deploy-vault` in both
   `DEPLOY_REPO_RETAINED_TENANTS` and
   `DEPLOY_REPO_DISCOVERY_TOMBSTONES`.
5. A CI guard fails if the retired wrapper is recreated, deploy-repo delivery is
   reintroduced in the namespace envelope, or either load-bearing override is
   removed.

## Consequences

### Positive

- Vault changes are reviewed directly in the cluster platform repository.
- The cluster's secret-zero system no longer depends on deploy-repo discovery or
  ref-bump delivery.
- ADR-0011 remains valid for real deploy repositories, while its `deploy-vault`
  worked example is clearly historical.
- The namespace envelope remains outside the prunable Vault workload tree.
- The retained-tenant and discovery-tombstone overrides provide complementary
  protection: one keeps the namespace envelope applied, and the other prevents
  re-adoption of the retired wrapper.

### Negative

- The fold creates a permanent exception to the visual expectation that
  `deploy-vault` behaves like an ordinary `deploy-*` tenant.
- The safety model depends on the override arrays staying in place while the
  namespace envelope remains tracked.
- Documentation must distinguish historical deploy-vault references from the
  current platform-owned Vault service.

### Neutral

- The imported Vault ADRs remain historical records with their original
  numbering preserved.
- The `deploy-vault` namespace name remains unchanged because it is part of the
  live Vault address, policy, certificate, and storage boundary.
- The fold does not change Vault's KMS auto-unseal, TLS, storage, VSO, backup,
  or exposure decisions.

## Assumptions

1. Vault remains the cluster's accepted secret-zero service.
2. The `deploy-vault` namespace remains the stable runtime namespace for Vault.
3. The generated tenant envelope can safely remain tracked without implying that
   Vault is still delivered by deploy-repo discovery.
4. The fold-invariant CI guard remains part of pull request validation because
   the Validate workflow runs on every pull request targeting `main`.

## Supersedes

- The `deploy-vault` worked example in
  [ADR-0011](0011-auto-discover-deploy-repositories.md). ADR-0011's
  auto-discovery decision remains current for real deploy repositories.

## Superseded by

None (current).

## Implementing PRs

- The Vault fold was implemented on 2026-06-15 by adopting Vault into
  `clusters/talos-cluster/apps/vault/`, retiring the generated deploy-repo
  wrapper, retaining the namespace envelope, and tombstoning discovery.
- The fold-invariant CI guard records and protects the steady-state contract.

## Related ADRs

- [ADR-0011](0011-auto-discover-deploy-repositories.md) - defines deploy-repo
  discovery and now retains `deploy-vault` only as a historical worked example.
- [ADR-0012](0012-vault-kms-auto-unseal-credential-delivery.md) - records the
  SOPS/Flux delivery model for Vault KMS auto-unseal credential material.
- [ADR-0013](0013-use-dedicated-vault-longhorn-storageclass.md) - records
  dedicated Vault storage placement.
- [ADR-0015](0015-use-vault-secrets-operator-for-workload-secrets.md) - records
  the VSO workload-secret consumption path that depends on Vault as a platform
  service.
- [Imported Vault ADRs](vault/) - preserve the original Vault design records
  relocated from the retired `deploy-vault` repository.

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | CM-2, CM-3 | Moves the secret-zero service into the cluster source-of-truth repository and records the ownership change. |
| NIST SP 800-53 Rev. 5 | CP-10, SC-28 | Keeps the Vault namespace and PVC boundary protected from app-tree prune failure modes. |
| NIST SP 800-190 | 4.1, 4.5 | Removes tenant-style delivery from platform secret infrastructure while retaining namespace network guardrails. |
| SSDF | PO.5, PS.3 | Documents the platform trust-root decision and the CI invariant that prevents regression. |
