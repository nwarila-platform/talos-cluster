# ADR-0014: Use a Stage-1 Local Backup Server for Backup and DR

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-12                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | PLAN section 7, ADR-0006, ADR-0012, deploy-vault TLS and Raft manifests |
| Informed       | future reviewers                        |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## Context and Problem Statement

The cluster now has real operational state in more than one place:

- S3 already holds Stage-0 rebuild-critical material: `secrets.yaml`,
  `age.agekey`, and regenerable/access material such as `talosconfig`.
- etcd holds Kubernetes state: CRDs, Flux state, Helm release records, RBAC,
  namespaces, PVC bindings, and Longhorn object references.
- Vault Raft now holds live trust state, including the internal PKI
  intermediate key, PKI roles, tokens, policies, and seal metadata.
- Longhorn holds persistent volume data, with Vault using the dedicated
  `longhorn-vault` StorageClass for new PVCs.

ADR-0006 placed daily etcd snapshots in S3. That target is now intentionally
mis-homed: S3 remains correct for the tiny Stage-0 cold-start tier, but bulk
operational state belongs on a local on-prem backup server that survives
ordinary cluster loss without turning AWS into the operational data store.

The recovery gap is no longer theoretical. The owner has already experienced
undetected Vault quorum loss for multiple days, the old etcd snapshot workflow
was disabled before Stage-1 existed, restore has never been drilled, and there
is not yet a remote re-image path. The backup design therefore must be
restore-first, not capture-only.

## Decision Drivers

1. Preserve the Stage-0/Stage-1 split: S3 is for rebuild-critical secrets only;
   Stage-1 is for operational state.
2. Treat Vault Raft snapshots as first-class recovery artifacts because Vault
   now holds the live PKI.
3. Retarget etcd snapshots away from S3 and onto Stage-1.
4. Keep backups independent of the services they recover. Vault backup and
   restore credentials must not exist only inside Vault.
5. Require a rehearsable restore drill with explicit pass criteria before node
   hardening depends on the backup posture.
6. Surface missed backups and near-expiry conditions before they become
   multi-day incidents.

## Considered Options

1. **Stage-1 local backup server for etcd, Vault Raft, and later Longhorn/PV.**
2. **Continue storing etcd and Vault snapshots in S3 with KMS.**
3. **Operator-workstation manual snapshots only.**
4. **Install an in-cluster backup operator first and use it as the DR root.**

## Decision Outcome

Chosen option: **Option 1, Stage-1 local backup server.**

Stage-0 S3 remains narrow and durable: it stores rebuild-critical secrets and
access material only. Stage-1 is a new local on-prem server, not yet built, that
stores sensitive operational snapshots:

| Artifact | Cadence target | Retention target | Notes |
| --- | --- | --- | --- |
| Stage-0 secrets | On every rebuild-secret change | Current plus prior known-good copy | Existing S3 path stays. No bulk operational data goes here. |
| etcd snapshot | Every 6 hours plus before risky platform changes | All runs for 14 days, daily for 90 days, monthly for 12 months | Captured with `talosctl etcd snapshot`; restores through `talosctl bootstrap --recover-from`. |
| Vault Raft snapshot | Hourly plus before/after PKI, policy, seal, or storage changes | All runs for 7 days, daily for 90 days, monthly for 12 months | Captured with `vault operator raft snapshot`. Seal-encrypted; restores only when the same KMS seal path works. |
| Longhorn/PV data | Future ADR | Future ADR | Not covered by this decision except as a Stage-1 storage-sizing driver. |

Every Stage-1 snapshot set should include a small manifest beside the snapshot:
UTC timestamp, source node/pod, tool versions, Git refs, artifact size, SHA256,
storage target, and restore compatibility notes. Snapshot files and manifests
are sensitive operational records and must never be committed to Git or exposed
publicly.

### Stage-1 Server Requirements

The local backup server must be outside the Talos cluster and outside Vault's
dependency chain. It should provide:

- Encrypted-at-rest storage with redundancy, such as a ZFS mirror or equivalent
  on encrypted disks. Start with at least 1 TiB usable capacity for snapshot
  history and leave a clear expansion path before Longhorn/PV backups land.
- A local upload API reachable from the operator workstation and the future
  protected cluster runner. A local S3-compatible endpoint is preferred because
  it works with ordinary tooling and is a natural future Longhorn target; SSH or
  HTTPS upload can be accepted if documented with the same access controls.
- TLS for the upload API, a private backup VLAN or equivalent network
  isolation, and firewall rules that allow only the operator workstation,
  protected runner namespace, and explicitly approved restore hosts.
- Separate write-only backup credentials per producer where the protocol
  supports it, and separate break-glass read/restore credentials. Store those
  credentials in SOPS or offline escrow, not only in Vault.
- Backup-server OS/config rebuild documentation in Git, with any disk unlock
  or recovery secret treated as Stage-0-class material if it is not purely
  offline/human-held. Bulk snapshot data still stays local.
- Scrub, disk-health, capacity, and replication alerts for the backup server
  itself.

### Interim Until Stage-1 Exists

Until the Stage-1 server is built, the acceptable interim is an
operator-workstation capture to encrypted local or removable media, with a
manifest and checksum. A temporary S3-with-KMS operational snapshot is only an
owner-approved stopgap when no local target exists and the trade-off is
explicit: it improves immediate recoverability but violates the intended
sovereignty boundary for bulk operational state. In all cases, snapshots remain
out of Git.

No live snapshots are created by this ADR. Capture automation and the first
actual drill are follow-up implementation steps.

### Automation Staging

Automation is staged deliberately:

1. **Now:** documented manual/scripted capture from the operator workstation to
   encrypted interim media or the Stage-1 server once built.
2. **Next:** Stage-1 upload and retention scripts for etcd and Vault, still
   runnable by the operator.
3. **Future:** a protected cluster-hosted runner or CronJob performs scheduled
   captures to Stage-1 using local/in-cluster credentials. This ties into the
   future runner feature and should not introduce a new AWS role or S3
   round-trip for operational snapshots.

Vault is now HTTPS. A local operator can port-forward Vault for one-off work,
but `https://127.0.0.1:8200` will not match the Vault serving certificate SANs.
That path is acceptable only as an explicit operator tunnel with
`VAULT_SKIP_VERIFY=true` or equivalent for the one command being run. The clean
automation path is an in-cluster job that talks to a DNS name present in the
Vault serving cert, such as the
`vault-N.vault-internal.deploy-vault.svc.cluster.local` pod FQDNs used by
deploy-vault, and mounts the Vault CA.

There is also a likely Vault policy gap: the current admin/automation policies
must be verified before any real capture. Backup needs read access to
`sys/storage/raft/snapshot`; restore is break-glass and may require update
access to `sys/storage/raft/snapshot` and/or
`sys/storage/raft/snapshot-force`. Do not assume `vault-admin` already grants
those paths.

### Restore Drill Requirement

A backup is not accepted as working until a restore drill passes. The drill must
prove both recovery primitives without endangering production:

- etcd: restore a selected snapshot into a sacrificial Talos control plane with
  `talosctl bootstrap --recover-from`.
- Vault: restore a selected Raft snapshot into a sacrificial Vault deployment
  using the same KMS auto-unseal path, then prove Vault unseals and the PKI
  state is present.

The restore drill runbook is
[`docs/runbooks/restore-drill-backup-dr.md`](../../runbooks/restore-drill-backup-dr.md).
Production restore remains an owner-gated emergency operation because it wipes
control-plane disks and/or overwrites Vault Raft state.

## Pros and Cons of the Options

### Option 1: Stage-1 local backup server (chosen)

- **Good, because** it matches the owner-approved Stage-0/Stage-1 DR layering.
- **Good, because** it keeps bulk state sovereign and local while leaving S3 as
  a small cold-start tier.
- **Good, because** it can store etcd, Vault, and later PV backups behind one
  local access and monitoring model.
- **Bad, because** the server does not exist yet, so interim captures remain
  manual until the owner builds it.

### Option 2: Continue S3 operational snapshots

- **Good, because** S3 is already durable and the old etcd script is close to
  usable as a capture mechanism.
- **Bad, because** it contradicts the storage split: operational state would
  live in AWS instead of the local Stage-1 tier.
- **Bad, because** the parked workflow also depended on missing/misaligned AWS
  role and runner plumbing.

### Option 3: Operator-workstation manual snapshots only

- **Good, because** it is immediately available and does not require new
  infrastructure.
- **Bad, because** it repeats the human-memory failure mode that caused the
  recovery gap. Manual capture is an interim, not the design.

### Option 4: In-cluster backup operator as DR root

- **Good, because** operators can provide polished schedules and retention.
- **Bad, because** an in-cluster controller cannot be the root recovery
  primitive for an etcd or Vault failure. It may become a producer of Stage-1
  artifacts later, not the trust root.

## Consequences

### Positive

- The docs now name Vault Raft as a crown-jewel backup artifact alongside etcd.
- ADR-0006's S3 snapshot target is superseded instead of left half-current.
- Recovery work is gated on a drill with pass criteria, not just the presence of
  snapshot files.

### Negative

- Recovery is still not complete until Stage-1 exists, automation is wired, and
  the drill passes.
- Vault restore depends on the KMS seal path. A KMS, STS, Roles Anywhere, or
  certificate failure can prevent a restored Vault from unsealing.
- Longhorn/PV data is explicitly deferred; etcd restores object references, not
  necessarily the bytes behind every PVC.

### Neutral

- The old `scripts/etcd-snapshot.sh` remained available as implementation
  material until [ADR-0026](0026-in-cluster-etcd-snapshot-pipeline.md) landed
  the in-cluster pipeline and deleted it (2026-07-11).
- A temporary S3 snapshot can still be chosen by the owner as an emergency
  stopgap, but it is not the accepted architecture.

## Confirmation

This ADR is confirmed when all of the following are true:

1. ADR-0006 is marked superseded by this ADR for the etcd-to-S3 design.
2. The top-level README points operators to the Stage-1/runbook design instead
   of claiming daily S3 etcd snapshots are active.
3. `docs/runbooks/restore-drill-backup-dr.md` documents owner-gated etcd and
   Vault restore drills with pass criteria.
4. A follow-up implementation provides Stage-1 capture scripts or workflows for
   both etcd and Vault.
5. Monitoring alerts when the newest Vault Raft snapshot is older than 90
   minutes, the newest etcd snapshot is older than 8 hours, any snapshot upload
   fails, backup-server capacity or disk health is degraded, or critical
   recovery certificates approach expiry.
6. The first restore drill records snapshot checksums, tool versions, elapsed
   restore time, pass/fail criteria, and any corrective actions.

## Assumptions

1. Stage-0 S3 continues to store only rebuild-critical material and remains
   independently reachable after a rack, cluster, or local backup-server loss.
2. The Stage-1 server will be built outside the Talos cluster and will not rely
   on Vault to decrypt or expose its own backup data.
3. Vault remains sealed by the same AWS KMS seal model when a Raft snapshot is
   restored. If the seal model changes, the Vault restore section of the runbook
   must be revised before the next drill.
4. The future runner feature can provide protected local-network execution
   without reintroducing AWS as the operational snapshot target.

## Supersedes

- [ADR-0006](0006-etcd-snapshot-automation.md), for the decision to store etcd
  operational snapshots in S3 and to treat capture-only automation as
  sufficient.

## Superseded by

None (current).

## Related ADRs

- [ADR-0003](0003-repo-as-cluster-source-of-truth.md) - declares the repo as
  the declarative source of truth; Stage-1 snapshots recover runtime state.
- [ADR-0006](0006-etcd-snapshot-automation.md) - superseded S3 etcd snapshot
  target.
- [ADR-0007](0007-capture-longhorn-as-managed-addon.md) - Longhorn is managed,
  but PV backup remains future work.
- [ADR-0012](0012-vault-kms-auto-unseal-credential-delivery.md) - records the
  KMS auto-unseal model that Vault snapshot restore depends on.
- [ADR-0013](0013-use-dedicated-vault-longhorn-storageclass.md) - reduces
  Vault storage single-node risk but does not replace off-host backups.
- [ADR-0021](0021-synology-nfs-backup-target-for-longhorn.md) - realizes the
  Longhorn/PV Stage-1 backup tier this ADR deferred, on the Synology NFS target.

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | CP-9 | Defines backup scope, cadence, retention, and storage tiers for etcd, Vault, and future PV data. |
| NIST SP 800-53 Rev. 5 | CP-10 | Requires a rehearsable restore drill with pass criteria before backups are accepted as working. |
| NIST SP 800-53 Rev. 5 | SC-28 | Requires encrypted-at-rest Stage-1 storage and sensitive snapshot handling outside Git. |
| NIST SP 800-53 Rev. 5 | AU-6 | Requires last-success, failure, capacity, and expiry monitoring so backup failures are noticed promptly. |
