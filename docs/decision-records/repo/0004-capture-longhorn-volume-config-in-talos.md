# ADR-0004: Capture Longhorn-Backing Volume Declarations in the Talos Machine Config

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-25                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

This repository declares two Talos `VolumeConfig`-family resources in `cluster/patches/volumes.yaml` and `scripts/generate.sh` appends them to every per-node generated machine config. The first (`VolumeConfig name=EPHEMERAL`) caps the ephemeral volume at 25 GiB; the second (`UserVolumeConfig name=longhorn`) carves out a 50–240 GiB Longhorn-backing user volume from the system disk. These declarations were discovered on every live node during the 2026-05-25 reconciliation; without them, `make apply` would tell every node to drop those volumes on the next reboot, destroying storage that production workloads depend on.

## Context and Problem Statement

During the 2026-05-25 reconciliation cycle, `talosctl apply-config --dry-run` against every live node revealed two extra top-level YAML documents present in every node's running machine config but absent from this repository's `cluster/patches/`:

```yaml
---
apiVersion: v1alpha1
kind: VolumeConfig
name: EPHEMERAL
provisioning:
  diskSelector:
    match: system_disk
  maxSize: 25GiB
---
apiVersion: v1alpha1
kind: UserVolumeConfig
name: longhorn
provisioning:
  diskSelector:
    match: system_disk
  maxSize: 240GiB
  minSize: 50GiB
```

A naive `make apply` from the pre-reconciliation repo state would have removed both documents from every node's applied machine config on the next reboot, dropping the Longhorn-backing user volume and reverting ephemeral sizing to the Talos default. Helm/Longhorn manages PersistentVolumes at the Kubernetes layer; it does not (and cannot) recreate a Talos-level user volume that the underlying machine config has stopped declaring. The Talos volume is a precondition for the Helm-managed Longhorn pods to mount anything.

The repository did not capture this state because `talosctl gen config` does not emit `VolumeConfig` / `UserVolumeConfig` documents in its default output, and the original bootstrap of this cluster added them out-of-band after the fact. The reconciliation cycle is the first time the repository attempts to be the declarative source of truth for the full machine config; bringing the volume declarations under repo control is the missing piece.

## Decision Drivers

1. **Source-of-truth completeness.** Per [ADR-0003](0003-repo-as-cluster-source-of-truth.md), this repository is the declarative source of truth for the cluster. State that exists on the cluster but not in the repo violates that promise — and the volume declarations are not optional state; they are storage primitives that real workloads depend on.
2. **No surprise data loss.** The next `make apply` must not silently drop volumes that production workloads depend on. The volume declarations being present in every generated config is the only way to guarantee that.
3. **Minimal disruption to existing automation.** `scripts/generate.sh` is already the documented operator workflow. The fix should extend it, not replace it.
4. **Honest about coupling.** The Longhorn Helm chart in `addons/longhorn/` (when authored) will mount this volume; the chart's `values.yaml` will reference `longhorn` as a disk tag. That coupling deserves to be documented somewhere a future reader will find.

## Considered Options

1. **Append a shared `cluster/patches/volumes.yaml` to every generated per-node config in `scripts/generate.sh`.**
2. **Make `volumes.yaml` per-role (CP vs worker), or per-node.**
3. **Add the volume declarations only via Helm (Longhorn chart values, `addons/longhorn/`).**
4. **Accept the drift and document it as "manage Longhorn volumes out-of-band."**

## Decision Outcome

Chosen option: **Option 1, append a single shared `cluster/patches/volumes.yaml` to every generated per-node config.**

`cluster/patches/volumes.yaml` contains the two volume documents verbatim. `scripts/generate.sh` defines an `append_volumes` shell function that `cat`s the file onto the end of every per-node config produced by `talosctl machineconfig patch`. The file is allowlisted in `.gitignore`. The result is byte-identical to what the live cluster has on every node — confirmed by structural diff against `.s3/recovered/live-machineconfigs/<ip>.machineconfig-resource.yaml`.

The append-after-patch approach is required because `talosctl machineconfig patch` (the tool the script uses for per-node strategic-merge overrides) only operates on the v1alpha1 main document; it cannot add new top-level kinds. Embedding the volume documents in `talosctl gen config`'s `--config-patch` flow was attempted and rejected — that flag has the same v1alpha1-only constraint.

## Pros and Cons of the Options

### Option 1: Single shared `volumes.yaml`, appended in `generate.sh` (chosen)

- **Good, because** the file is the single place to look up volume sizing decisions, and a future change is a one-file edit.
- **Good, because** it matches the live cluster's pattern of declaring identical volume documents on every node.
- **Good, because** the `append_volumes` function in `generate.sh` is small (~10 lines) and easy to audit.
- **Neutral, because** CPs receive the user volume declaration even though `allowSchedulingOnControlPlanes: false` prevents Longhorn pods from running there. The declaration is idle on CPs but harmless and matches live.
- **Bad, because** the append step is brittle if a future Talos version changes how multi-doc machine configs are validated; the script currently has no schema check on the appended content beyond what `talosctl validate --strict` does after the fact.

### Option 2: Per-role or per-node volume patches

- **Good, because** it lets CPs and workers have different volume sizes if that ever becomes useful.
- **Bad, because** it adds files without solving a real problem: the live cluster has the same declarations on every node, so the per-role split would just duplicate content with no behavioural difference.

### Option 3: Volume declarations only via Helm (Longhorn chart values)

- **Bad, because** Helm cannot create a Talos-level user volume. Longhorn's PVs depend on the underlying `UserVolumeConfig` already existing on the node.
- **Bad, because** moving the declaration to Helm hides a hard storage dependency inside an addon, where a reviewer evaluating the Talos config would not see it.

### Option 4: Accept the drift, document as out-of-band

- **Bad, because** it directly contradicts [ADR-0003](0003-repo-as-cluster-source-of-truth.md), which the reconciliation cycle that revealed this drift exists to enforce.

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Presence check.** `cluster/patches/volumes.yaml` MUST exist and MUST contain exactly one `VolumeConfig name=EPHEMERAL` and one `UserVolumeConfig name=longhorn` document.
2. **Generation check.** `scripts/generate.sh` MUST invoke an append step that copies `cluster/patches/volumes.yaml` verbatim onto every per-node generated config (both control-plane and worker).
3. **Empty-diff check.** A structural comparison of every generated per-node config (`.s3/generated/{controlplane,worker}/<name>.yaml`) against the live machine config (`talosctl get machineconfig --nodes <ip>`) MUST report zero extra kinds and zero missing kinds.
4. **Editorial rule.** Changes to volume sizing or disk selectors are architectural decisions and MUST be recorded as a superseding repo-tier ADR.
5. **Helm coupling.** When the Longhorn Helm chart is authored in `addons/longhorn/`, the chart's `values.yaml` MUST reference the user-volume name `longhorn` (matching the `name:` field in `UserVolumeConfig`). The chart MUST NOT redeclare or override the Talos-level volume.

## Consequences

### Positive

- `talosctl diff` reports zero remaining drift between the repo and every live node — the precondition for safe `make apply` is satisfied.
- A future reader sees the Longhorn storage precondition in the same `cluster/patches/` directory as every other Talos-level setting, not buried in a Helm chart.
- The next change to volume sizing is a one-file edit plus a follow-up ADR.

### Negative

- `scripts/generate.sh` now has a non-trivial post-patch append step that future maintainers must remember when authoring new patch types. The function name `append_volumes` is specific to volumes; a more general extension mechanism may be needed if other multi-doc kinds (e.g., `KmsEncryptionConfig`, `ExtensionServiceConfig`) need to be declared in the future.
- CPs carry an idle Longhorn user-volume declaration. Storage is reserved on the system disk but never used. Functionally harmless; cosmetically wasteful.

### Neutral

- The volume documents do not appear in `talosctl gen secrets` output and do not need to be regenerated when secrets are rotated.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. Talos 1.12+ continues to accept `VolumeConfig` and `UserVolumeConfig` as separate top-level YAML documents in an applied machine config.
2. The system disk on every node remains large enough to satisfy the 25 GiB ephemeral cap + 50 GiB Longhorn minimum simultaneously. Current install disks are all `/dev/nvme0n1`; size is not enumerated here.
3. The Longhorn Helm chart, when authored, will be configured to consume the user volume named `longhorn` via Talos disk-tag discovery rather than by creating its own backing storage.

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

The PR that introduces this ADR also introduces `cluster/patches/volumes.yaml`, edits `scripts/generate.sh` to add the `append_volumes` step, and adds the new patch to `.gitignore` allowlist.

## Related ADRs

- [ADR-0001 (org)](../org/0001-use-architecture-decision-records.md) — defines the ADR format used here.
- [ADR-0003 (repo)](0003-repo-as-cluster-source-of-truth.md) — establishes the source-of-truth obligation this ADR fulfils for volume declarations.

## Compliance Notes

This ADR records a storage-declaration capture decision. The Longhorn-backed user volume is a precondition for any Kubernetes PersistentVolumeClaim backed by Longhorn; capturing it in source control aligns with NIST 800-53 CM-2 (Baseline Configuration) by ensuring the cluster's storage baseline is reconstructible from this repository alone.

| Framework              | Control / Practice ID                              | Potential Evidence Contribution                                                                                       |
| ---------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5  | CM-2 (Baseline Configuration)                      | Volume declarations are now in source control; the cluster's storage baseline is reconstructible from the repo alone. |
| NIST SP 800-53 Rev. 5  | CP-9 (System Backup)                               | Knowing the Talos-level volume sizes is a precondition for any Longhorn backup/restore plan.                          |
