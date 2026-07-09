# ADR-0021: Synology NFS Backup Target for Longhorn Stage-1 DR

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-09                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0014, ADR-0007, ADR-0013, ADR-0012, Longhorn v1.11.2 backupstore source/docs, live node-side mount verification, PLAN section 10 |
| Informed       | future reviewers                        |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## Context and Problem Statement

ADR-0014 established the Stage-1 local backup server for operational DR state but
explicitly deferred **Longhorn / PV data** to a "Future ADR" and left the Stage-1
endpoint unbuilt, with an operator-workstation capture as the accepted interim.
This ADR is that future decision for the Longhorn backup tier, and it replaces the
interim endpoint with a real appliance.

The interim Longhorn backup target was an NFS export on the owner's Windows/WSL
workstation (`nfs://10.69.12.11:/srv/nfs/backup`). That path had three structural
problems:

- **Session-bound, not an appliance.** The WSL NFS server only ran while the owner
  was logged in; a reboot dropped the target until logon.
- **Being decommissioned.** The workstation is migrating Windows to Linux; once
  retired, Stage-1 Longhorn backups would silently break.
- **It holds crown-jewel recovery data.** No Vault Raft snapshots are retained
  today, so Vault DR currently depends on the Longhorn volume backup of the Vault
  PVCs. The backup target therefore protects the live PKI trust root, not just
  ordinary PV bytes.

We need a durable, always-on, sovereign NFS target that is inside neither the Talos
cluster nor Vault's dependency chain, provable before the workstation is retired,
and configured to a no-compromise reliability/security standard.

## Decision Drivers

1. Realize ADR-0014's Stage-1 tier for the Longhorn/PV artifact with a real
   always-on appliance, not a workstation.
2. Keep the target sovereign and independent of the cluster and of Vault.
3. Use only officially supported, deterministic configuration — no unsupported
   hacks that revert on firmware updates.
4. Add tamper/ransomware resistance (an immutable copy) — the "1" in 3-2-1-1-0 that
   Stage-0 S3 does not provide (SSE-S3, no Object Lock; see the escrow reality).
5. Coexist surgically on a shared production appliance without touching existing
   business data.
6. Zero backup gap during cutover, with a clean rollback.

## Considered Options

**Endpoint:**

1. **Synology RS3621rpxs NFS export** (chosen).
2. **The Linux operator box (`10.69.112.100`) as a new interim NFS server.**
3. **Keep the Windows/WSL box.**

**Backup protocol on the appliance:**

- NFS (Longhorn-native, credential-free) vs an S3-compatible endpoint (MinIO /
  Synology Object Storage).

**NFS protocol version:**

- Pin NFSv4.1 vs leave Longhorn's default 4.2->4.1 auto-negotiation vs force real
  NFSv4.2 on the appliance.

## Decision Outcome

Chosen endpoint: **Option 1, the Synology `TCNHQ-BKUP01` (RS3621rpxs, DSM 7.2.1),
NFS**, with the backup target:

```
nfs://10.69.128.115:/volume1/longhorn-backup?nfsOptions=nfsvers=4.1,actimeo=1
```

The appliance is a rackmount, redundant-PSU NAS with a 25 TB Btrfs volume on RAID6
(2-disk fault tolerance), on its own storage VLAN (`10.69.128.0/24`), reachable
from the cluster nodes (`10.69.112.0/24`) across routed inter-VLAN. It is a shared
production appliance (it also serves an ESXi datastore and Active Backup for
Business / M365 / Google backups), so the entire change is confined to one new
dedicated share.

### Appliance-side configuration (applied via the DSM UI, the only supported path)

- **Dedicated Btrfs share** `longhorn-backup`, with **data checksum** (Btrfs
  self-healing + scrubbing) and a **100 GB quota** (a blast-radius cap so this
  workload can never fill the volume and starve the business shares).
- **NFS export scoped per-host to the six node IPs** (cp1/2/3 = `.63/.64/.65`,
  w1/2/3 = `.68/.69/.70`), generated as
  `rw,sync,crossmnt,all_squash,sec=sys,anonuid=1024,anongid=100`.
- **`sync`** (not async) for backup integrity; **non-privileged ports denied**.
- **Daily immutable snapshots, retain 30, 7-day WORM lock.**

### NFS-version sub-decision — pin 4.1 (the "no-compromise" analysis)

- Longhorn v1.11.2 supports NFS **4.0, 4.1, and 4.2**. With no options it probes
  `4.2 -> 4.1 -> 4.0` and mounts the first that works; passing `?nfsOptions=`
  skips the probe and mounts once with exactly those options.
- **DSM tops out at NFSv4.1.** `/proc/fs/nfsd/versions` reports `-4.2`, there is no
  4.2 toggle in the DSM UI through DSM 7.3/7.4, and Synology publishes no 4.2
  roadmap. The only way to force 4.2 is an unsupported `echo +4.2 >
  /proc/fs/nfsd/versions` plus an `nfsd` restart, which would (a) drop the live
  ESXi datastore mid-I/O, (b) revert on the next DSM update/reboot (silently
  breaking a client pinned to 4.2), (c) may not initialize on the Synology 4.4
  kernel, and (d) provides no capability Longhorn's backup format uses (its
  4.2-only features - server-side copy, sparse SEEK_HOLE/DATA, `fallocate`,
  labeled NFS - are irrelevant to backup blobs).
- Therefore **4.1 is not a compromise for this workload; forcing 4.2 would be** -
  it would trade reliability and supportability for a version number. We pin
  `nfsvers=4.1` for a deterministic single mount, plus `actimeo=1` (Longhorn's own
  default, which mitigates the known NFSv4.1 backup-list cache-staleness issue).

### NFS over S3

NFS was chosen over a Synology S3/MinIO endpoint because it is Longhorn-native,
credential-free (no key to store, rotate, or leak - access is controlled by source
IP + VLAN), and was already the proven, working mechanism. An S3 endpoint would add
a credentialed service surface for no benefit at this scale.

### Cluster-side changes (this PR)

- `addons/longhorn/values.yaml` -> the target URL above.
- `clusters/talos-cluster/apps/dr-backup/ciliumnetworkpolicy-egress.yaml` -> egress
  CIDR `10.69.12.11/32` -> `10.69.128.115/32`.
- `docs/runbooks/dr-stage1-backup.md` -> rewritten for the Synology.

### Security design (the attack each layer closes)

- **Per-host export scoping** - closes any other host on the storage VLAN mounting
  our backups. AUTH_SYS trusts the client-asserted UID, so IP scoping + the
  isolated storage VLAN are the real access control.
- **`all_squash` -> admin** - closes a compromised node using NFS root to read or
  write NAS files as root. This is deliberately stricter than the `no_root_squash`
  the co-resident ESXi datastore requires; the backup store needs no remote root.
  Verified: a root-written probe file landed as `uid 1024 (admin)` on the NAS.
- **`sync`** - closes the window where an async-acked write is lost on NAS power
  loss before flush.
- **Immutable Btrfs snapshots (daily, retain 30, 7-day lock)** - close backup
  tampering / ransomware. Snapshots live outside the NFS-exported tree, so a
  compromised cluster credential (even root-over-NFS) can overwrite or delete the
  *live* backup files but cannot touch the snapshots; only a DSM administrator can,
  and within the 7-day WORM window not even that. The live share stays writable so
  Longhorn can still rotate (retain 14) - this is why WORM/WriteOnce was rejected
  for the share itself (see below).
- **DSM firewall left unchanged** - it currently guards the whole shared appliance
  and enabling/scoping it risks the ESXi/ABB services; flagged as separate hardening
  rather than imposed by this change.

### Immutability: snapshots, not WriteOnce/WORM on the share

DSM offers a WriteOnce (WORM) share mode, but it locks files against modify, delete,
and rename for a retention period. Longhorn's backupstore must continuously delete
and rotate old backups and rewrite metadata and lock files, so a WORM share would
break backups and grow unbounded. Immutable **snapshots** give the same tamper
guarantee for point-in-time copies while leaving the live share mutable - the
correct architecture for a rotating backup target.

### Verification (proof, not assumption)

Before any cutover, a throwaway pod on w1 mounted the new share and proved the full
path: mounted at `vers=4.1` (`rw,hard,sec=sys`), wrote/read/**deleted** a file
(rotation capability), the file landed squashed to `admin(1024)`, and the NAS saw
`clientaddr=10.69.112.68` - confirming cross-VLAN routing and that the per-host
export scoping matches the post-SNAT node source IP. The old WSL target remained
live throughout, so cutover carries no backup gap.

## Pros and Cons of the Options

### Endpoint Option 1: Synology NFS (chosen)

- **Good, because** it is an always-on, redundant (RAID6 + Btrfs checksum),
  purpose-built appliance outside the cluster and Vault.
- **Good, because** Btrfs immutable snapshots add the tamper-resistant copy that
  neither the workstation nor Stage-0 S3 provided.
- **Good, because** it is on an isolated storage VLAN with per-host export scoping.
- **Bad, because** it is a shared appliance that also holds business data, so our
  workload and a production business coexist on one device (mitigated by a
  dedicated share, quota, and per-host export).
- **Bad, because** NFS transport is unencrypted (see Consequences).

### Endpoint Option 2: The Linux operator box as new interim

- **Good, because** it is already up and in the node subnet.
- **Bad, because** it re-couples backups to the operator workstation we are trying
  to stop depending on, has only ~18 GB free on its OS disk (no dedicated backup
  volume), and would mean a second migration later. Rejected as a step backward.

### Endpoint Option 3: Keep the Windows/WSL box

- **Bad, because** it blocks the Windows decommission and is session-bound. Rejected.

### Pinned NFSv4.1 vs auto-negotiate vs forced 4.2

- **Pinned 4.1 (chosen):** deterministic single mount, clean logs, no reliance on
  the fallback path. Does not auto-adopt 4.2 if DSM ever adds it (a one-line change
  later) - an acceptable trade for determinism.
- **Auto-negotiate:** would land on 4.1 today and self-adopt 4.2 if DSM ever ships
  it, but wastes a failed 4.2 probe per mount and relies on the fallback path.
- **Force 4.2 on the appliance:** rejected - unsupported, disrupts the ESXi
  datastore, non-persistent, and provides no Longhorn benefit.

## Consequences

### Positive

- The Longhorn/PV Stage-1 tier deferred by ADR-0014 is now realized on a durable,
  sovereign appliance, unblocking the Windows workstation decommission.
- Backups gain a NAS-controlled immutable copy the cluster cannot reach, materially
  improving the DR posture against ransomware and credential compromise.
- The configuration is fully supported and deterministic, and was proven end-to-end
  before cutover.

### Negative

- **Unencrypted transport.** NFS AUTH_SYS has no on-wire encryption (no TLS, no
  krb5p). This is mitigated by the isolated storage VLAN, per-host scoping, and the
  fact that the crown-jewel payload (Vault Raft) is barrier-encrypted inside the
  backup. Kerberos/NFS-over-TLS was considered and rejected as fragile with
  Longhorn and overkill against a VLAN-isolated target. **Gap to revisit** if
  non-encrypted sensitive PVs are later backed up here.
- **Share not encrypted at rest.** DSM share encryption was declined (Vault data is
  already encrypted; DSM encryption adds a 143-char path limit and key management).
  Same revisit trigger as above for future non-encrypted PVs.
- **Shared appliance across trust domains.** A single NAS serves both this cluster's
  DR and unrelated business backups; mitigated by the dedicated share, quota, and
  scoping, but it is not a dedicated backup host.
- **No offsite copy yet.** This is one local copy; the offsite/offline "1" of
  3-2-1 remains future work.
- **Snapshot deletion is possible by a DSM administrator** outside the 7-day WORM
  window - a separate trust boundary. The DSM admin credentials used for setup are
  rotated afterward and are never stored in-cluster.

### Neutral

- NFS was chosen over an S3-compatible endpoint; the choice can be revisited if a
  credentialed, TLS object endpoint is later preferred.
- The old WSL target is retained and functional until the cutover is proven, then
  retired; the interim WSL setup docs and scripts are superseded by the runbook.

## Confirmation

This ADR is confirmed when all of the following are true:

1. `addons/longhorn/values.yaml`, the `dr-backup` egress policy, and the Stage-1
   runbook point at the Synology target and are reconciled by Flux.
2. Longhorn reports the backup target as available.
3. A **new** Vault volume backup completes to the Synology after cutover (Longhorn
   Backup CR `Completed` and the backup files present under
   `/volume1/longhorn-backup` on the NAS).
4. The first daily immutable snapshot of `longhorn-backup` exists on the NAS.
5. The retired WSL NFS target is decommissioned only after the above pass.

## Assumptions

1. Cilium masquerades pod egress to the node IP (verified: the NAS observed the
   node source IP), so the per-host export scoping is correct.
2. The DSM admin credentials used for setup are DSM-admin only (not the NFS data
   path, which is IP + VLAN controlled) and are rotated post-setup.
3. The Synology remains always-on and on its isolated storage VLAN, and its RAID6 +
   Btrfs redundancy and scrubbing remain healthy.
4. Longhorn continues to support NFSv4.1 across upgrades; if a future Longhorn
   requires 4.2, the `nfsOptions` pin and this ADR are revisited.
5. Vault DR continues to rely on Longhorn volume backups of the Vault PVCs until
   Raft snapshots are retained; this target therefore stays crown-jewel-class.

## Supersedes

- None. This ADR **realizes** the Longhorn/PV Stage-1 tier that
  [ADR-0014](0014-use-stage-1-local-backup-server-for-dr.md) deferred, and retires
  the interim Windows/WSL NFS target documented in the Stage-1 runbook.

## Superseded by

None (current).

## Related ADRs

- [ADR-0014](0014-use-stage-1-local-backup-server-for-dr.md) - established the
  Stage-1 local backup server and deferred Longhorn/PV to this ADR.
- [ADR-0007](0007-capture-longhorn-as-managed-addon.md) - Longhorn is the managed
  addon whose backups this target stores.
- [ADR-0013](0013-use-dedicated-vault-longhorn-storageclass.md) - the
  `longhorn-vault` StorageClass whose volumes are the primary backup subjects.
- [ADR-0012](0012-vault-kms-auto-unseal-credential-delivery.md) - the KMS
  auto-unseal model a restored Vault volume depends on.
- [ADR-0006](0006-etcd-snapshot-automation.md) - the sibling etcd Stage-1 tier.

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | CP-9 | Provides the durable, sovereign Stage-1 storage location for Longhorn/PV backups, with capacity quota and redundancy. |
| NIST SP 800-53 Rev. 5 | CP-9(5) | Immutable, WORM-locked NAS snapshots provide a backup copy protected from cluster-side deletion or alteration. |
| NIST SP 800-53 Rev. 5 | CP-10 | The pre-cutover node-side mount test plus prior Longhorn restore drills confirm recoverability before reliance. |
| NIST SP 800-53 Rev. 5 | SC-7 | Per-host NFS export scoping plus an isolated storage VLAN constrain access to the backup target. |
| NIST SP 800-53 Rev. 5 | SC-8 | Notes the residual unencrypted-transport gap and its VLAN/payload-encryption mitigations. |
| NIST SP 800-53 Rev. 5 | SC-28 | Btrfs checksum + scrubbing protect at-rest integrity; at-rest confidentiality relies on Vault barrier encryption of the payload, with a documented revisit trigger. |
| NIST SP 800-53 Rev. 5 | SI-7 | Btrfs data checksum with self-healing detects and repairs silent corruption of backup data. |
