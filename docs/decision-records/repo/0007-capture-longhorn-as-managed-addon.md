# ADR-0007: Capture the Longhorn Helm Release as a Managed Addon

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-26                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | N/A (Accepted)                          |

## TL;DR

This repository captures the live Longhorn Helm release (chart `longhorn-1.11.1` / app `v1.11.1` in `longhorn-system`) as a managed addon at `addons/longhorn/values.yaml`. The values are the deltas-from-chart-default that the live release was installed with on 2026-04-04 and reads to be present today: `defaultDataPath: /var/mnt/longhorn` (couples to the Talos `UserVolumeConfig` from [ADR-0004](0004-capture-longhorn-volume-config-in-talos.md)); `defaultReplicaCount: 2` (small-cluster sweet spot); `nodeDownPodDeletionPolicy: delete-both-statefulset-and-deployment-pod` (failover correctness); `storageMinimalAvailablePercentage: 10` (chart default 25% is over-conservative for the 50–240 GiB user volume); control-plane tolerations on `longhornManager` and `longhornDriver` (lets CPs also host Longhorn replicas); `persistence.defaultClass: true` + `defaultClassReplicaCount: 2`. Configuring a Longhorn S3 backup target (and the `RecurringJob` schedules that depend on it) is intentionally out of scope for this ADR and tracked as a follow-up cycle.

## Context and Problem Statement

Longhorn has been running on this cluster since 2026-04-04 as a Helm release in the `longhorn-system` namespace. Until this ADR:

- [ADR-0004](0004-capture-longhorn-volume-config-in-talos.md) captures the **Talos-side** half: every node carries a `UserVolumeConfig` named `longhorn` that reserves 50–240 GiB from the system disk and is auto-mounted at `/var/mnt/longhorn`. ADR-0004 §Confirmation §5 commits to writing the Helm side: "When the Longhorn Helm chart is authored in `addons/longhorn/`, the chart's `values.yaml` MUST reference the user-volume name `longhorn`."
- The **Helm-side** half — chart version, install values, StorageClass strategy, replica policy — exists only as cluster state stored inside etcd (and inside Helm 3's release-tracking Secret in `longhorn-system`). Nothing in `addons/`. The cluster's storage configuration was a debt the repository acknowledged but had not paid.

The recoverability gap was concrete: [ADR-0006](0006-etcd-snapshot-automation.md) makes etcd snapshots cover release **tracking** ("a release named `longhorn` exists at version 1.11.1"), but the values that produced that release live in Helm 3's release Secret. The same etcd snapshot does carry that Secret, so a `talosctl bootstrap --recover-from` restore would also restore Helm's idea of the release. But:

1. The pair (etcd snapshot + secrets bundle) becomes the only source of truth for Longhorn config. A reviewer reading the repo cannot see why Longhorn is configured the way it is.
2. Recovery to a *new* environment (different bucket, different IP range) by replaying the repo state requires `helm install -f <values>` — and the values weren't in the repo.
3. ADR-0004 §5 is a written promise; honoring it is the only way to keep ADR-0004 in good standing.

The values themselves (read via `helm get values longhorn -n longhorn-system -o yaml` on 2026-05-26) are not numerous and not surprising. The repo capture is mostly a transcription with comments explaining why each non-default exists.

## Decision Drivers

1. **Pay ADR-0004 §5's debt.** The Helm side of Longhorn must be in the repo.
2. **Make the storage layer reviewable.** A reader inspecting `addons/longhorn/values.yaml` should be able to understand the replica strategy, the data-path coupling to Talos, and the scheduling decisions without `helm get`-ing a running release.
3. **No behavior change.** This ADR captures *what is*, not *what should be*. The next `helm upgrade -f addons/longhorn/values.yaml` against the live cluster should be a no-op.
4. **Stay narrow.** Backup target, RecurringJobs, and StorageClass customization are separate cycles, each with their own decisions to record.

## Considered Options

1. **Capture the user-supplied values verbatim.**
2. **Capture the full effective values (user values + chart defaults), so the file is fully self-describing.**
3. **Capture only a "minimum viable" subset and let chart defaults handle the rest.**
4. **Skip the Helm capture; rely on etcd snapshots + Helm 3 release Secret for recovery.**

## Decision Outcome

Chosen option: **Option 1, capture the user-supplied values verbatim with annotated comments.**

`addons/longhorn/values.yaml` contains the same seven deltas the live release was installed with, annotated to explain each non-default. A future `helm upgrade -f addons/longhorn/values.yaml` against the existing release is by construction a no-op against the cluster, which is the right behavior for a capture-only cycle. Migrating from "what the cluster has" to "what the repo says" is therefore safe — no surprise reconfiguration on the next reconciliation.

The full effective values (Option 2) would be hundreds of lines, most of which are chart defaults that change with chart upgrades. Capturing them would either freeze us against a single chart version or pollute the repo with churn at every Renovate-driven chart bump. Option 1 keeps the file tightly scoped to *this cluster's intent*.

Option 3 (a minimum-viable subset) is undefined — every value the live release carries was set deliberately. None of them can be safely dropped to chart defaults without changing cluster behavior.

Option 4 (rely on etcd + Helm Secret) preserves recoverability but not reviewability. It also creates an awkward coupling: a configuration change to Longhorn would have to be made on the cluster (via `helm upgrade` from a local checkout that re-derives the values) and then back-ported to the repo. That inverts the source-of-truth direction ([ADR-0003](0003-repo-as-cluster-source-of-truth.md)).

## Pros and Cons of the Options

### Option 1: Capture user-supplied values verbatim (chosen)

- **Good, because** the file is small (~30 lines of values + comments), reviewable in one read.
- **Good, because** `helm upgrade -f addons/longhorn/values.yaml` against the current cluster is by construction a no-op — no behavior change risk.
- **Good, because** chart bumps via Renovate change only `--version`; the values file stays stable.
- **Bad, because** a reader without chart-default knowledge can't fully understand the final effective config without inspecting the upstream chart. Mitigated by the per-key comments explaining the non-default's purpose.

### Option 2: Capture full effective values

- **Good, because** the repo becomes fully self-describing — no need to read the upstream chart.
- **Bad, because** the values file would be hundreds of lines, most of them duplicating chart defaults.
- **Bad, because** chart upgrades introduce diff churn on chart-default fields, drowning real config changes.
- **Bad, because** any value left at chart default that the chart later changes a default for would silently change cluster behavior without an explicit ADR or commit.

### Option 3: Minimum viable subset, drop the rest

- **Good, because** the repo has only the most-impactful settings.
- **Bad, because** the live release was installed with seven specific non-defaults, each chosen for a reason. None is "minimum viable to drop." Dropping any would change behavior.

### Option 4: Rely on etcd + Helm Secret

- **Good, because** zero new files in the repo.
- **Bad, because** breaks ADR-0003's source-of-truth model: cluster state would be the canonical Longhorn config, not the repo.
- **Bad, because** ADR-0004 §Confirmation §5 explicitly commits to writing values.yaml. This option would silently break that promise.

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Presence check.** `addons/longhorn/values.yaml` MUST exist and MUST include the seven non-default settings listed in the TL;DR.
2. **Data-path coupling check.** `defaultSettings.defaultDataPath` MUST equal `/var/mnt/<name>` where `<name>` matches the `name:` field of the `UserVolumeConfig` declared in `cluster/patches/volumes.yaml`. Changing one without the other leaves Longhorn writing to a different volume than the one Talos provisions.
3. **Replica-count coupling check.** `defaultSettings.defaultReplicaCount` and `persistence.defaultClassReplicaCount` MUST be equal. Diverging the two would let StorageClass-allocated PVCs get a different replica count from the global default — a confusing footgun.
4. **No-op-on-upgrade check.** A `helm upgrade longhorn longhorn/longhorn --version <pinned> -f addons/longhorn/values.yaml --dry-run` against the live cluster MUST report no behavioral diff. A reviewer SHOULD run this before merging any change to `values.yaml`.
5. **Chart-version pinning.** The install command in README MUST pass `--version <X.Y.Z>` matching the live release. Renovate manages bumps; merging a chart bump is an architectural change that does not require a superseding ADR unless the values shape changes.
6. **Out-of-scope check.** This ADR is capture-only. Adding a `BackupTarget`, `RecurringJob`, or changing `StorageClass` shape requires a separate ADR.

## Consequences

### Positive

- [ADR-0004 §5](0004-capture-longhorn-volume-config-in-talos.md) is now satisfied. The Talos-side `UserVolumeConfig` and the Helm-side `defaultDataPath` are explicitly paired in the repo.
- A reviewer can read `addons/longhorn/values.yaml` and `cluster/patches/volumes.yaml` together and understand the full storage configuration in two files.
- Disaster recovery via `talosctl bootstrap --recover-from` ([ADR-0006](0006-etcd-snapshot-automation.md)) is augmented: even if the Helm 3 release Secret is corrupted during restore, `helm upgrade --install` from the repo reconstitutes the release deterministically.
- Renovate now tracks the Longhorn chart version. Bumps land as PRs with `talosctl validate` + drift detection providing the merge gates.

### Negative

- **The cluster has no off-host backup target.** Longhorn's `BackupTarget` resource is empty (`URL: ""`). All replicas live on workers' system disks. A two-worker simultaneous failure loses replica data. This ADR does not address that; it is the natural next cycle (probably ADR-0008).
- **The cluster has no scheduled snapshots/backups.** No `RecurringJob` resources exist. Even if a `BackupTarget` were configured, nothing would push backups to it on a schedule. Same follow-up cycle as above.
- **Drift detection between Helm values and repo is not yet automated.** `scripts/drift-check.sh` ([ADR-0003](0003-repo-as-cluster-source-of-truth.md)) compares Talos machine configs only. A future cycle could extend it to compare `helm get values longhorn -n longhorn-system -o yaml` against `addons/longhorn/values.yaml`.

### Neutral

- The seven values captured are unchanged from the live release. No `helm upgrade` is run by this ADR's implementing PR — capturing the state in the repo doesn't require touching the cluster.
- StorageClass-level tunables (e.g., `numberOfReplicas` per SC, `staleReplicaTimeout`) are not customized in the live release; chart defaults apply. Capturing them in `values.yaml` would be over-specification per Option 1's reasoning.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. The Longhorn upstream chart at `longhorn/longhorn` continues to use the `defaultSettings`, `longhornManager`, `longhornDriver`, and `persistence` top-level keys. Schema renames would require a values-file rework.
2. The chart's `defaultDataPath` continues to map directly to the host directory Longhorn writes replica data to. (This has been stable across many Longhorn chart releases.)
3. The Talos `UserVolumeConfig`'s auto-mount pattern at `/var/mnt/<name>` is preserved across Talos versions ([ADR-0004](0004-capture-longhorn-volume-config-in-talos.md) §Assumptions §1 already takes this on; this ADR depends on the same assumption).

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

The PR that introduces this ADR also introduces `addons/longhorn/values.yaml`, adds the install command to the README's Step 10 section alongside the other Helm-installed addons, and updates `.gitignore` + `docs/decision-records/README.md`.

A follow-up PR (tracked) will configure a Longhorn `BackupTarget` plus `RecurringJob` snapshot/backup schedules. That PR is its own ADR (probably ADR-0008) because configuring a backup target involves an S3 bucket/prefix decision, an IAM principal decision (Longhorn needs its own creds, not the operator's), and a retention strategy.

## Related ADRs

- [ADR-0003 (repo)](0003-repo-as-cluster-source-of-truth.md) — establishes the source-of-truth invariant this ADR honors for Longhorn.
- [ADR-0004 (repo)](0004-capture-longhorn-volume-config-in-talos.md) — captures the Talos-side `UserVolumeConfig`; this ADR captures the Helm-side counterpart and closes the §Confirmation §5 commitment.
- [ADR-0006 (repo)](0006-etcd-snapshot-automation.md) — etcd snapshots cover the cluster-shape recovery primitive; this ADR ensures the Helm release definition is reproducible in the repo even if Helm 3's release Secret is lost during restore.

## Compliance Notes

This ADR captures workload-storage configuration in source control. It does not by itself add off-host backups of Longhorn-managed volume data; that's the follow-up cycle.

| Framework              | Control / Practice ID                              | Potential Evidence Contribution                                                                                                  |
| ---------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5  | CM-2 (Baseline Configuration)                      | The cluster's storage layer is now declaratively captured at the Helm tier in addition to the Talos tier.                        |
| NIST SP 800-53 Rev. 5  | CM-3 (Configuration Change Control)                | Changes to Longhorn behavior must now go through the PR + drift-check workflow rather than ad-hoc `helm upgrade`.                |
| NIST SP 800-53 Rev. 5  | CP-9 (System Backup)                               | Combined with [ADR-0006](0006-etcd-snapshot-automation.md), the cluster's recoverability story includes the Longhorn install recipe; the volume-data backup leg is tracked as a follow-up. |
