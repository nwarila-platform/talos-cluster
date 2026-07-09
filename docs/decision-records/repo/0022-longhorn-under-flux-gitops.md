# ADR-0022: Bring Longhorn Under Flux GitOps

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-09                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0007, ADR-0008, ADR-0013, ADR-0021, Longhorn v1.11.2 chart values, existing Flux Pattern B manifests |
| Informed       | future reviewers                        |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## Context and Problem Statement

Longhorn has been the cluster's default replicated storage layer since the first
Talos production build, but it remained a manual Helm release installed from the
README runbook. ADR-0007 captured the Helm values in
`addons/longhorn/values.yaml`, and ADR-0008 intentionally deferred Longhorn until
after smaller Flux migrations proved the takeover pattern.

That deferral is now the main GitOps gap. ADR-0021 changed the repository's
Longhorn backup target to the Synology NFS share and correctly described the
desired GitOps end state, but merging the values change alone did not make the
live Longhorn release reconciled by Flux. The live backup target is a runtime
Longhorn `BackupTarget` CR, and Helm values seed that setting only at install.

The repository needs Flux to adopt the existing `longhorn` Helm release without
reinstalling Longhorn or disturbing running workloads, while preserving a clean
from-scratch rebuild order for Longhorn-dependent resources.

## Decision Drivers

1. Adopt the live Longhorn release without uninstalling, reinstalling, or
   restarting Longhorn workloads as part of the manifest change.
2. Keep the chart version pinned to `1.11.2`, matching `LONGHORN_VERSION` in
   `cluster/config.env`.
3. Inline values that byte-match `addons/longhorn/values.yaml` so the first
   helm-controller reconcile is a near-no-op.
4. Keep HelmRepository and HelmRelease resources namespace-local for
   `--no-cross-namespace-refs` compatibility.
5. Ensure DR rebuilds create the Longhorn namespace, release, and CRDs before
   applying Longhorn `Node`, `RecurringJob`, and `StorageClass` resources used by
   Vault.
6. Avoid committing generated machine configs, kubeconfigs, secrets, or live
   cluster output.

## Considered Options

1. Leave Longhorn as a manual Helm release.
2. Manage Longhorn's rendered manifests as raw Kustomize resources.
3. Adopt the existing release with a Flux HelmRelease.

## Decision Outcome

Chosen option: **Option 3, adopt the existing release with a Flux HelmRelease.**

`clusters/talos-cluster/apps/longhorn/` now follows the same layered Pattern B
used by Kyverno and Vault Secrets Operator:

- the parent Kustomize index declares the `longhorn-system` Namespace and a child
  Flux `Kustomization`;
- the child Flux `Kustomization` points at `apps/longhorn/release`, waits up to
  15 minutes, and health-checks the `longhorn-system/longhorn` HelmRelease;
- the release directory contains the namespace-local `HelmRepository` and
  `HelmRelease`.

The HelmRelease:

- uses `releaseName: longhorn` in namespace `longhorn-system`;
- pins `spec.chart.spec.version: "1.11.2"`;
- references the same-namespace `HelmRepository` without
  `sourceRef.namespace`;
- sets `install.crds: Create` and `upgrade.crds: CreateReplace`;
- disables Helm tests;
- sets `upgrade.remediation.remediateLastFailure: false` and
  `upgrade.cleanupOnFail: true`;
- inlines values that mirror `addons/longhorn/values.yaml` byte-for-byte after
  removing the HelmRelease indentation.

The first reconcile is expected to adopt the existing Helm release. Because the
chart version and user values match the intended repo state, the rendered
workload manifests should be unchanged. The only intended delta is the Helm seed
ConfigMap value for the backup target moving from the retired WSL NFS endpoint to
the Synology target already accepted by ADR-0021; the live runtime backup target
remains the Longhorn `BackupTarget` CR until the owner performs and verifies the
adoption.

DR-rebuild ordering of the Longhorn-dependent Vault storage policy (the
`longhorn-vault` StorageClass, the `vault-daily-backup` RecurringJob, and the
Longhorn `Node` tags) behind Longhorn is a **tracked follow-up, not part of this
change**. Promoting `apps/longhorn-vault-storage/` to its own `dependsOn`
Kustomization would move those resources out of the root Kustomization's
inventory, and the root would prune the live Longhorn `Node` CRs on the Vault
storage nodes (w1/w2/w3) before the child recreates them — churning replica/disk
state on the crown-jewel volumes. That ownership handoff must be made prune-safe
first (the ADR-0017 adopt-before-prune / `kustomize.toolkit.fluxcd.io/prune:
disabled` technique). Flux's retry behavior already makes the current flat wiring
self-healing on a from-scratch rebuild (the Longhorn CRs simply re-reconcile once
the chart has registered the CRDs), so `apps/longhorn-vault-storage/` is left
unchanged here.

## Pros and Cons of the Options

### Option 1: Leave Longhorn Manual

- **Good, because** it avoids changing the current ownership model for the most
  stateful addon.
- **Bad, because** it preserves the ADR-0008 deferred work and leaves chart
  updates, values drift, and DR rebuild order dependent on operator memory.
- **Bad, because** ADR-0021's repository change to the backup target would still
  not be reconciled into the Helm release by Flux.

### Option 2: Raw-Manifests Kustomization

- **Good, because** Kustomize could order raw resources behind a Flux
  `Kustomization`.
- **Bad, because** Longhorn is distributed as a Helm chart and its CRD lifecycle,
  hooks, labels, and release metadata are designed for Helm ownership.
- **Bad, because** rendering and committing chart output would create a large
  generated artifact surface and make future chart upgrades harder to review.

### Option 3: HelmRelease Adopt (chosen)

- **Good, because** it matches the existing Flux addon pattern and helm-controller
  can adopt an existing Helm release with the same release name, namespace,
  version, and values.
- **Good, because** chart version, CRD policy, and values become reviewable
  manifests while preserving Helm as the chart lifecycle engine.
- **Good, because** the Longhorn-dependent Vault storage policy can depend on the
  Longhorn HelmRelease being healthy during DR rebuilds.
- **Bad, because** `addons/longhorn/values.yaml` and
  `HelmRelease.spec.values` are duplicated until an automated drift check is
  added. Reviewer attention enforces equality for now, per ADR-0008.

## Consequences

### Positive

- Longhorn reaches GitOps parity with the other Flux-managed cluster addons.
- Longhorn's namespace, HelmRepository, and HelmRelease are now declared for a
  from-scratch rebuild; ordering the Longhorn-dependent Vault storage policy
  behind Longhorn is identified and tracked as a prune-safe follow-up.
- Renovate's Longhorn chart pin in `cluster/config.env` now has a corresponding
  Flux HelmRelease version field that reviewers can keep in step.
- ADR-0021's Synology target is represented in both the human-readable values file
  and the reconciled HelmRelease values.

### Negative

- Values drift now has two in-repo copies to review:
  `addons/longhorn/values.yaml` and `HelmRelease.spec.values`.
- The initial adoption still needs owner-gated live verification before merge
  because Longhorn holds persistent volume data.

### Neutral

- The live backup target remains a Longhorn runtime `BackupTarget` CR. Helm values
  seed that setting at install, but they do not prove the live CR has changed
  after an already-installed release.
- The migration changes who manages Longhorn; it does not intentionally change
  Longhorn workload configuration.

## Confirmation

This ADR is confirmed when all of the following are true:

1. `kubectl kustomize clusters/talos-cluster/apps/` renders cleanly.
2. `HelmRelease.spec.values` deep-equals `addons/longhorn/values.yaml`.
3. The helm-controller adoption completes without Longhorn workload restarts.
4. The Longhorn manager DaemonSet age is preserved across adoption.
5. All Longhorn volumes remain `Healthy`.
6. The live Longhorn `BackupTarget` CR still points at the Synology NFS target.
7. Flux reports the `longhorn` Kustomization Ready.

## Assumptions

1. Flux helm-controller continues to adopt existing Helm releases idempotently
   when release name, namespace, chart version, and user values match.
2. The live Longhorn release is still chart `1.11.2` when this PR is merged.
3. The owner performs the live adoption verification before allowing the change
   onto `main`.

## Supersedes

None. This ADR realizes ADR-0008's deferred Longhorn migration step.

## Superseded by

None (current).

## Related ADRs

- [ADR-0007](0007-capture-longhorn-as-managed-addon.md) - captured the
  Longhorn Helm values this ADR inlines into the Flux HelmRelease.
- [ADR-0008](0008-gitops-via-flux.md) - established Flux and explicitly deferred
  Longhorn as the cautious stateful-addon migration.
- [ADR-0013](0013-use-dedicated-vault-longhorn-storageclass.md) - defines the
  Longhorn-dependent Vault StorageClass and Node tag policy now gated behind
  Longhorn readiness.
- [ADR-0021](0021-synology-nfs-backup-target-for-longhorn.md) - defines the
  Synology backup target mirrored into the Longhorn Helm values.

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | CM-2 | Captures Longhorn's desired Helm release configuration in the declarative cluster baseline. |
| NIST SP 800-53 Rev. 5 | CM-3 | Moves Longhorn changes into PR-reviewed GitOps instead of manual Helm commands. |
| NIST SP 800-53 Rev. 5 | CM-6 | Records Longhorn chart version, CRD handling, and Helm values as version-controlled configuration settings. |
| NIST SP 800-53 Rev. 5 | CP-10 | Improves DR rebuild determinism by ordering Longhorn before dependent storage policy resources. |
