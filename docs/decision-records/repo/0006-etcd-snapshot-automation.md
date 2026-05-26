# ADR-0006: Daily etcd Snapshots to S3 for Cluster Recovery

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

A scheduled GitHub Actions workflow (`.github/workflows/etcd-snapshot.yaml`) runs `scripts/etcd-snapshot.sh` daily at 03:00 UTC. The script captures an etcd bbolt snapshot via `talosctl etcd snapshot` from a non-bootstrap CP and uploads it KMS-encrypted to `s3://793496711039-terraform/nwarila-platform/talos-cluster/etcd-snapshots/YYYY-MM-DD/snapshot-HHMMSSZ.db`. Combined with the existing `secrets/secrets.yaml` mirror in the same bucket, this is sufficient to recover the cluster via `talosctl bootstrap --recover-from` after a CP-quorum failure. The cycle that introduces this ADR sets up the capture path; restore-testing against a sacrificial cluster is out of scope and tracked as a follow-up.

## Context and Problem Statement

Until this ADR, the cluster had no recovery option for catastrophic CP failure. Every Kubernetes object — CRDs, Helm release tracking (including the kubelet-csr-approver release added in ADR-0005), RBAC, namespaces, ServiceAccounts, every Longhorn `Volume`/`Replica` reference, every `PersistentVolumeClaim` binding — lives only in etcd, replicated across the three CP nodes. With three CPs the cluster tolerates one CP loss; two CPs lost simultaneously (a bad apply on cp1 + a hardware failure on cp2, a coordinated reboot under power-event conditions, a misconfigured `make apply` that wipes both `/var/lib/etcd`s before quorum is restored, an etcd corruption that propagates) leaves quorum unrecoverable.

The recovery story at that point would be:
1. Rebuild the cluster from `make bootstrap` against the existing Talos machine configs.
2. Lose every CRD, every Helm release, every Service account, every Longhorn metadata reference.
3. Reapply every addon by hand from the README runbook.
4. Attempt to re-attach Longhorn replicas from the workers' system disks (Longhorn stores both metadata and data; without the cluster-side `Volume` resources, the worker-side replicas are orphaned).
5. Hope production state survives. Some workloads — anything with cluster-managed state in CRDs — definitely will not.

Talos provides `talosctl etcd snapshot <local-path>` for exactly this. The command streams the etcd bbolt DB from the leader to the talosctl client. Combined with the secrets bundle this repo already mirrors in S3, the pair forms a complete recovery primitive: `talosctl bootstrap --recover-from /path/to/snapshot.db --talosconfig <new-config>` against a freshly wiped CP node restores the entire cluster control plane to the snapshot's state.

The gap until now: no scheduled execution. An operator who remembered to run `talosctl etcd snapshot` quarterly would have a quarterly RPO; an operator who forgot would discover the gap during the incident. Industry convention for production Talos clusters is daily automated snapshots to an off-host encrypted store. This ADR adopts that convention.

## Decision Drivers

1. **Recoverability.** Without snapshots, the cluster's recovery story tops out at "rebuild from machine configs and lose all in-etcd state." That is unacceptable for a cluster carrying real workloads.
2. **No new dependencies.** Talos's built-in `etcd snapshot` subcommand and the existing S3 bucket + KMS key are sufficient. No new operator (Velero, Longhorn's etcd backup, a third-party CRD) needs to be installed in the cluster.
3. **Off-host encrypted storage.** Snapshots embed cluster secrets and tokens; they must be encrypted at rest and stored outside any CP node.
4. **Discoverable retention.** The S3 path must let an operator find the right snapshot quickly during an incident (date-bucketed paths, not opaque hashes).
5. **Frictionless automation.** Daily snapshots should run without operator interaction and surface a failure in a way the on-call notices (CI failure email + GitHub issue on scheduled-job failure).

## Considered Options

1. **Daily `talosctl etcd snapshot` via GitHub Actions → S3.**
2. **Velero installed in the cluster, configured to back up etcd + PVCs to S3.**
3. **Longhorn-only backups via Longhorn's S3 backup target.**
4. **Manual snapshots on a quarterly cadence; no automation.**

## Decision Outcome

Chosen option: **Option 1, scheduled `talosctl etcd snapshot` to S3.**

`scripts/etcd-snapshot.sh` is the orchestrator. `.github/workflows/etcd-snapshot.yaml` runs it on a daily 03:00 UTC schedule from a self-hosted runner. The snapshot lands at `s3://793496711039-terraform/nwarila-platform/talos-cluster/etcd-snapshots/YYYY-MM-DD/snapshot-HHMMSSZ.db` with `--sse aws:kms` using the same KMS key (`arn:aws:kms:us-east-1:793496711039:key/6c9426c6-448d-46d1-97dc-0b8ca9bd15df`) the `secrets/` objects already use. Object metadata records source CP node, source IP, cluster name, Talos version, and Kubernetes version — useful at restore time when matching a snapshot to a compatible cluster bootstrap.

This ADR is explicitly scoped to **capture**, not to **restore-testing**. A restore drill that takes a snapshot from production and replays it against a sacrificial test cluster is the natural next ADR (ADR-0007 candidate). Until that drill happens, the snapshots are unproven recovery primitives — better than the prior state of having none, but not formally verified.

## Pros and Cons of the Options

### Option 1: `talosctl etcd snapshot` to S3 (chosen)

- **Good, because** it uses Talos's native, supported snapshot subcommand. Sidero documents this as the recommended DR primitive for production Talos clusters.
- **Good, because** the entire automation is ~100 lines of bash + one workflow. No new in-cluster operators to maintain.
- **Good, because** S3 + KMS is the same posture already used for `secrets/secrets.yaml`. No new credential surface.
- **Good, because** snapshots are date-bucketed in S3; an operator finding "the snapshot from yesterday afternoon" is one `aws s3 ls` away.
- **Neutral, because** snapshots are 50–300 MiB each (per Sidero's published guidance on bbolt DB sizes for small-to-medium clusters). At 7d STANDARD + 365d Glacier retention, total storage is well under $5/mo.
- **Bad, because** the cycle adds **capture** without proving **restore**. Untested backups are a known anti-pattern. The follow-up restore-drill ADR mitigates this, but the gap exists between this ADR landing and that drill being run.

### Option 2: Velero in-cluster

- **Good, because** Velero can also back up PVCs (Longhorn data), giving a single tool for both etcd-state and persistent-volume DR.
- **Good, because** Velero's restore tooling is more polished than `talosctl bootstrap --recover-from` (named restores, partial-namespace restore, hooks).
- **Bad, because** it installs ~6 new CRDs + a controller + a node-agent daemonset. Significant new attack surface for a cluster this size.
- **Bad, because** Velero stores its own state in-cluster; a CP-quorum failure that destroys etcd also destroys Velero's restore plan. You'd need an out-of-cluster bootstrap to restore Velero before Velero can restore the rest. The chicken-and-egg dance is the whole problem Talos `etcd snapshot` solves directly.
- **Bad, because** it overlaps with Talos's built-in snapshot tooling without adding capabilities for *etcd-state* recovery specifically.
- **Reconsider when:** Longhorn data backups become urgent and a unified tool is more valuable than minimum-surface DR. Probably ADR-0008+ territory after Longhorn is captured.

### Option 3: Longhorn-only backups

- **Good, because** addresses worker-side data, which is the largest single failure-domain concern.
- **Bad, because** doesn't touch etcd state at all. Cluster-level objects (CRDs, RBAC, Helm releases) are still unrecoverable.
- **Reconsider when:** combined with this ADR's etcd snapshots, as a complementary cycle. Both can exist independently.

### Option 4: Manual quarterly snapshots

- **Good, because** zero automation work.
- **Bad, because** the operator-discipline assumption is identical to the assumption that made ADR-0003 necessary in the first place (out-of-band cluster changes drifting from repo). Manual cadences fail the moment an operator is busy, on vacation, or forgets. The 38-day undocumented scale-out this cluster's repo previously missed is direct evidence the discipline is unreliable.

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Presence check.** `.github/workflows/etcd-snapshot.yaml` and `scripts/etcd-snapshot.sh` MUST exist. The workflow MUST include a daily cron schedule (cron expression no less frequent than once per day) AND `workflow_dispatch`.
2. **Encryption check.** Every uploaded snapshot object MUST report `ServerSideEncryption: aws:kms` via `aws s3api head-object`. A CI script MAY assert this after each snapshot upload (the snapshot script already calls `head-object` post-upload to verify the object landed; extending it to verify encryption metadata is a small follow-up).
3. **Recency check.** At least one snapshot object MUST exist in `s3://${S3_BUCKET}/${S3_PREFIX}etcd-snapshots/` with a `LastModified` timestamp newer than 25 hours. Operationally: the workflow's scheduled-failure issue is the human-readable signal; a CI assertion could be added in a follow-up if drift between scheduled runs becomes a concern.
4. **Source-node check.** The snapshot script MUST prefer a non-bootstrap CP as source node. The bootstrap node MAY be used only when no non-bootstrap CP is reachable.
5. **Restore documentation.** `README.md` MUST contain a "Disaster Recovery" runbook section documenting the `talosctl bootstrap --recover-from` command sequence with concrete examples (no placeholders that an operator has to translate during an incident).
6. **Restore drill.** A future repo-tier ADR MUST record the first restore drill (snapshot pulled, played into a sacrificial cluster, control plane verified). Until that ADR exists, the snapshots are unproven; this ADR's `Status` field stands but a banner notice belongs in the README runbook.

## Consequences

### Positive

- The cluster has a recovery primitive. Worst-case incident becomes "find the most recent snapshot in S3 and replay it" rather than "rebuild from scratch and lose all CRD/RBAC/Helm state."
- Snapshot age — recovery point objective (RPO) — is 24 hours by default. For a cluster of this size with no high-frequency cluster-state mutations, that's adequate.
- Recovery from a single bad apply (e.g., a future operator who runs `make apply` against a repo state that wipes a CRD) is now bounded — pull the previous day's snapshot, restore, retry the apply with the corrected repo.

### Negative

- Snapshots are unproven until a restore drill is documented in a follow-up ADR. The first drill SHOULD be run before any operational dependency forms on these snapshots being viable.
- The S3 bucket accumulates snapshots; without a lifecycle policy, storage cost grows ~50–300 MiB per day. The bucket has no current lifecycle rules (verified 2026-05-25); this ADR's recommended lifecycle is documented inline but not auto-applied:

   ```bash
   aws s3api put-bucket-lifecycle-configuration --bucket 793496711039-terraform \
     --lifecycle-configuration file://lifecycle.json
   ```

   where `lifecycle.json` contains a rule scoped to prefix `nwarila-platform/talos-cluster/etcd-snapshots/` that transitions to GLACIER_IR after 30 days and expires after 365 days. Applying this is an operator decision because the bucket is shared with Terraform state and other prefixes; the lifecycle rule must be added without disturbing those.

- Each scheduled run takes ~30–60s of self-hosted runner time. Trivial.

### Neutral

- Snapshots embed every cluster secret + bearer token. The KMS encryption + S3 bucket's `PublicAccessBlockConfiguration` ensure they're not readable without explicit IAM access. Anyone with read access to the bucket's KMS-decrypted objects already has cluster-secrets access via the `secrets/secrets.yaml` mirror; the snapshots don't widen that surface.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. `talosctl etcd snapshot` continues to produce a bbolt DB compatible with `talosctl bootstrap --recover-from` across Talos minor versions. Sidero's compatibility commitment is that snapshots from version N are restorable on version N or N+1; mixing major versions would invalidate older snapshots.
2. The S3 bucket `793496711039-terraform` continues to be reachable from the self-hosted runner with the configured `AWS_ROLE_ARN` having `s3:PutObject` and `kms:Encrypt` on the relevant prefix + key.
3. Cluster size remains small enough that snapshot files stay under a few hundred MiB. A future scale-out to hundreds of nodes / thousands of CRDs may warrant streaming snapshots directly to S3 (Talos's `etcd snapshot` does not currently stream; the workflow downloads the whole file to the runner first).

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

The PR that introduces this ADR also introduces `scripts/etcd-snapshot.sh`, `.github/workflows/etcd-snapshot.yaml`, the README runbook section, and the `.gitignore` allowlist entries.

A follow-up PR (tracked) will:
1. Apply the recommended S3 lifecycle rule.
2. Run the first restore drill against a sacrificial cluster.
3. Author the restore-drill ADR (ADR-0007 candidate) documenting the drill result.

## Related ADRs

- [ADR-0003 (repo)](0003-repo-as-cluster-source-of-truth.md) — establishes the "repo is source of truth" claim. This ADR closes the recoverability counterpart: declarative truth recovers the cluster *shape*, etcd snapshots recover the *state*.
- [ADR-0005 (repo)](0005-kubelet-csr-approver.md) — introduces the kubelet-csr-approver Helm release whose state lives in etcd. Without snapshots, a CP-quorum failure would lose tracking of the release; with snapshots, the release reappears in the recovered cluster.

## Compliance Notes

This ADR records a disaster-recovery primitive. Combined with [ADR-0003](0003-repo-as-cluster-source-of-truth.md) (declarative state) and the existing S3 secrets mirror, it constitutes the cluster's full backup posture for control-plane state. Persistent-volume data (Longhorn replicas on workers) is NOT covered by this ADR; that's a follow-up concern.

| Framework              | Control / Practice ID                              | Potential Evidence Contribution                                                                                              |
| ---------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5  | CP-9 (System Backup)                               | Daily encrypted snapshots of etcd state to off-host storage. RPO ≤ 24h.                                                       |
| NIST SP 800-53 Rev. 5  | CP-10 (System Recovery and Reconstitution)         | `talosctl bootstrap --recover-from` is the documented reconstitution procedure; this ADR ensures the input artifact exists.   |
| NIST SP 800-53 Rev. 5  | SC-28 (Protection of Information at Rest)          | Snapshots are stored with `--sse aws:kms` using the same customer-managed KMS key as the cluster's secrets bundle.            |
| NIST SP 800-53 Rev. 5  | CM-2 (Baseline Configuration)                      | Combined with [ADR-0003](0003-repo-as-cluster-source-of-truth.md), the repo + the snapshot form a complete baseline that is both declarative *and* state-bearing. |
