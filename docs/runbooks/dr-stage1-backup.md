# DR Stage 1 Backup

This runbook is the operator how-to/reference for the DR Stage 1 backup lifecycle
for the Talos cluster. ADR-0014 records the decision to use a local Stage 1 backup
server; [ADR-0021](../decision-records/repo/0021-synology-nfs-backup-target-for-longhorn.md)
records the decision to realize the Longhorn/PV tier of that server on a dedicated
Synology NFS share.

Stage 1 protects Longhorn volume data by sending Longhorn backups to a dedicated
NFS share on the Synology `TCNHQ-BKUP01` appliance. This replaces the retired
interim NFS export that ran in WSL on the owner's Windows workstation; the same
Longhorn NFS backup protocol is kept.

## Architecture

The data path is:

1. Vault uses Longhorn volumes through the `longhorn-vault` StorageClass (ADR-0013).
   No Vault Raft snapshots are retained today, so these Longhorn volume backups are
   the current Vault DR artifact — treat them as crown-jewel-class.
2. The `vault-daily-backup` Longhorn RecurringJob backs up matching volumes.
3. Longhorn writes backup data to
   `nfs://10.69.128.115:/volume1/longhorn-backup?nfsOptions=nfsvers=4.1,actimeo=1`.
4. The NFS server is the Synology `TCNHQ-BKUP01` (RS3621rpxs, DSM 7.2.1), a Btrfs
   volume on RAID6, on its own storage VLAN `10.69.128.0/24`. It is an always-on
   appliance (redundant PSU), not session-bound like the retired WSL target.
5. Access is controlled by a per-node-IP NFS export on the NAS plus the `dr-backup`
   egress CiliumNetworkPolicy; the mount is pinned to NFSv4.1.

The Synology is a shared production appliance (it also serves an ESXi datastore and
Active Backup for Business / M365 / Google backups). Everything here is confined to
one dedicated share, `longhorn-backup`; no existing share or export is touched.

## Backup target configuration

The Longhorn Helm values set the target:

```yaml
defaultBackupStore:
  backupTarget: "nfs://10.69.128.115:/volume1/longhorn-backup?nfsOptions=nfsvers=4.1,actimeo=1"
  backupTargetCredentialSecret: ""
```

The `nfsOptions=nfsvers=4.1` pin makes Longhorn mount once at NFSv4.1 (DSM's
maximum) instead of probing 4.2 -> 4.1; `actimeo=1` is Longhorn's default and avoids
the known NFSv4.1 backup-list cache-staleness issue. See ADR-0021 for the full
rationale (4.2 gains nothing for Longhorn's backup format and DSM has no supported
4.2).

The Vault backup job is committed at
`clusters/talos-cluster/apps/longhorn-vault-storage/recurringjob-vault-backup.yaml`:

```yaml
apiVersion: longhorn.io/v1beta2
kind: RecurringJob
metadata:
  name: vault-daily-backup
  namespace: longhorn-system
spec:
  task: backup
  cron: "17 8 * * *"
  retain: 14
  concurrency: 1
  groups:
    - default
```

Retention is 14 Longhorn backups for the selected Vault volumes. Treat this as
local operational recovery; the NAS-side immutable snapshots (retain 30) provide the
tamper-resistant copy, and an offsite copy remains future work.

## NAS-side configuration (Synology)

Applied through the DSM Web UI, the only supported path for share + NFS + snapshot
config. The `synoshare` / `/etc/exports` CLI is internal and undocumented, and DSM
regenerates `/etc/exports` from its own config, so shell edits are unsupported and
non-persistent.

Shared folder `longhorn-backup` on the Btrfs volume:

- Data checksum for advanced data integrity: enabled (Btrfs self-healing + scrubbing).
- Shared folder quota: 100 GB — a blast-radius cap so this workload cannot fill the
  volume and starve the co-resident business shares.
- No share encryption (the Vault payload is already barrier-encrypted) and no
  WriteOnce/WORM on the share (Longhorn must be able to delete/rotate and rewrite
  metadata — see immutable snapshots below).

NFS export rules — one per node IP, all identical:

- Clients: `10.69.112.63`, `.64`, `.65` (cp1/2/3) and `.68`, `.69`, `.70` (w1/2/3).
- Read/Write; Squash = Map all users to admin (`all_squash` -> `anonuid=1024`);
  Security = sys; asynchronous OFF (`sync`); non-privileged ports OFF; access to
  mounted subfolders ON (`crossmnt`).
- Generated form:
  `rw,sync,no_wdelay,crossmnt,all_squash,insecure_locks,sec=sys,anonuid=1024,anongid=100`.

Immutable snapshots (tamper/ransomware protection):

- Snapshot Replication: daily schedule, retain 30, immutable snapshots with a 7-day
  lock (WORM).
- Snapshots live outside the NFS-exported tree, so a compromised cluster credential
  (even root-over-NFS) can overwrite or delete the live backup files but cannot touch
  the snapshots; only a DSM administrator can, and not within the 7-day lock.
- WORM on the *share itself* was rejected: it would block Longhorn's required
  delete/rotate and metadata rewrites. Immutable snapshots give the tamper guarantee
  while leaving the live share mutable.

The DSM admin credentials used for this setup are DSM-admin only (the NFS data path
uses AUTH_SYS / source IP, not the admin password) and are rotated after setup.

## Network and access control

- The Synology is on its own storage VLAN `10.69.128.0/24`; the nodes are on
  `10.69.112.0/24` with routed inter-VLAN reachability.
- The `dr-backup` egress CiliumNetworkPolicy allows egress to `10.69.128.115/32` on
  TCP 2049.
- Cilium masquerades pod egress to the node IP, so the NAS sees the node source IP
  (verified: a w1 mount showed `clientaddr=10.69.112.68`). The per-host export is
  scoped to exactly those six node IPs.
- AUTH_SYS trusts the client-asserted UID, so IP scoping + VLAN isolation are the
  real access control; `all_squash` prevents a remote client acting as root on the NAS.

## Health Checks

Run these after cutover, after any NAS or network change, and periodically.

In Kubernetes, confirm Longhorn sees the target and the RecurringJob:

```bash
kubectl -n longhorn-system get settings.longhorn.io backup-target backup-target-credential-secret
kubectl -n longhorn-system get recurringjobs.longhorn.io vault-daily-backup
```

Confirm recent backups completed within the expected daily window:

```bash
kubectl -n longhorn-system get backups.longhorn.io \
  -o custom-columns='NAME:.metadata.name,STATE:.status.state,SNAPSHOT:.status.snapshotCreatedAt,ERR:.status.error'
```

On the Synology (DSM UI or SSH), confirm the export and the immutable snapshots:

- Control Panel -> Shared Folder -> `longhorn-backup` -> NFS Permissions lists the six node IPs.
- Snapshot Replication -> `longhorn-backup` shows a daily schedule, retain 30,
  immutable (7-day lock), and recent snapshots.
- `/etc/exports` (root) shows the six `rw,sync,...,all_squash,...` rules for
  `/volume1/longhorn-backup`.

Optional deeper check: a throwaway pod that statically mounts
`10.69.128.115:/volume1/longhorn-backup` with `-o nfsvers=4.1,actimeo=1` and
writes/reads/deletes a probe file proves the full path end-to-end (this is the
pre-cutover verification method; keep it clean and delete the pod, PVC, and PV
afterward).

## Longhorn Restore Procedure

Restore Longhorn data into a new volume first. Do not overwrite the production
Vault PVC as a first move.

1. Choose the backup timestamp from Longhorn.
2. In Longhorn, open the backup and choose restore to a new volume.
3. Name the restored volume with the source workload and timestamp.
4. Keep the restored volume detached until a scratch workload is ready.
5. Create a scratch PVC that binds to the restored Longhorn volume, or use the
   Longhorn UI/API flow that creates the PVC from the restored volume.
6. Mount the restored PVC into an isolated scratch pod or isolated Vault
   deployment.
7. Verify file ownership, volume contents, and expected Vault Raft data before
   any production cutover.
8. For a production emergency, get owner approval for the exact backup
   timestamp and the target PVC cutover plan before replacing anything.

### Restore Drill Log

Note: the 2026-06-22 and 2026-06-23 drills below ran against the interim WSL NFS
target (`10.69.12.11`), now retired. The restore procedure is target-agnostic; the
Synology cutover (ADR-0021) does not change it.

2026-06-22 Vault restore drill: PASS.

- Backup used: `backup-vault-0-dr-stage-1-20260622155753` for live PVC `data-vault-0` / Longhorn volume `pvc-b92dcad8-4461-4952-9c9c-9822eda6d673`.
- Restore target: new throwaway Longhorn volume `vault-restore-drill` with `spec.fromBackup` set to the selected backup URL and `numberOfReplicas: 1`.
- Restore completion: after creation, Longhorn reported `state=detached`, `restoreRequired=false`, and `actualSize=299892736`; Longhorn reported `robustness=unknown` while detached, then `state=attached`, `robustness=healthy`, `restore=false`, and `actualSize=299999232` when the scratch verifier pod mounted the restored volume.
- Read-only verification: scratch namespace `vault-restore-drill` was PSA `restricted`; static PV `vault-restore-drill-pv` used CSI `readOnly: true`; pod `vault-restore-reader` mounted the PVC read-only at `/restored`. Restored data contained `raft/raft.db` and `vault.db`. Restored sizes were `/restored/raft/raft.db` 32.0M, `/restored/vault.db` 16.0M, and `du -sh /restored` 19.3M. Live size comparison: this run performed a **read-only** `kubectl exec` into live `vault-0` (`ls`/`du` only — no mutation), reading `/vault/data/raft/raft.db` 33M, `/vault/data/vault.db` 17M, and `du -sh /vault/data` 20M; live Vault was verified undisturbed afterward (pods stayed `2/2 Running`). The drill boundary was **subsequently tightened to no live-Vault exec**; the 2026-06-23 re-run honored that tightened boundary by taking the live size baseline from the Longhorn volume CR (`status.actualSize`) instead.
- Cleanup: deleted scratch namespace `vault-restore-drill`, static PV `vault-restore-drill-pv`, and throwaway Longhorn volume `vault-restore-drill`. Post-cleanup checks showed the drill namespace, PV, and volume absent; the three live Vault Longhorn volumes remained attached and healthy, and live Vault pods stayed `2/2 Running`.

2026-06-23 Vault restore drill (independent re-run): PASS.

- Backup used: `backup-vault-0-dr-stage-1-20260622155753` (state `Completed`, `status.size` 299892736) for live PVC `data-vault-0` / Longhorn volume `pvc-b92dcad8-4461-4952-9c9c-9822eda6d673`. Backup URL `nfs://10.69.12.11:/srv/nfs/backup?backup=backup-vault-0-dr-stage-1-20260622155753&volume=pvc-b92dcad8-4461-4952-9c9c-9822eda6d673`.
- Restore target: new throwaway Longhorn volume `vault-restore-drill` (Longhorn v1.11.2) created as a `Volume` CR with `spec.fromBackup` set to the backup URL, `numberOfReplicas: 1`, `dataEngine: v1`, node tag `vault`. No live `data-vault-*` volume was reused, renamed, patched, detached, or deleted.
- Restore completion: Longhorn reached `state=detached`, `restoreRequired=false`, `actualSize=299896832` (matches the backup `size` 299892736), then `state=attached`/`robustness=healthy` once the scratch reader mounted it read-only.
- Read-only verification: scratch namespace `vault-restore-drill` was PSA `restricted`; static PV `vault-restore-drill-pv` used CSI `readOnly: true` with `persistentVolumeReclaimPolicy: Retain`; PSA-compliant pod `vault-restore-reader` (busybox, `runAsNonRoot`, UID/GID 65532, `allowPrivilegeEscalation: false`, drop ALL, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`) mounted the PVC read-only at `/restored`. Restored data contained Vault's Raft layout: `vault.db` (16801792 B, 16.0 MiB) and `raft/raft.db` (33583104 B, 32.0 MiB), owned `65532:65532` with `raft/` mode `drwx--S---`, file mtime `Jun 22 15:57` matching the backup snapshot. The restored `vault.db` begins with a valid bbolt meta-page header (magic `0xED0CDAED`, bytes `ed da 0c ed`, at offset 16; version 02; pageSize 4096); `raft/raft.db` is present with a matching page-0 header (its bbolt magic/version were not separately dumped). This confirms the restore is a real, correctly-shaped Vault BoltDB store — it is NOT a full DB-integrity check (meta-page checksum, the second meta page, interior/body pages, non-truncation of the tail) nor an application-recovery proof; those are deferred to the Vault-Level Restore Outline / next drill. A `touch` into `/restored` was rejected with "Read-only file system", confirming the mount was read-only.
- Size consistency vs live: this run did not exec into the live Vault pod (to stay strictly off live Vault); the live baseline was read from the Longhorn volume CR `status.actualSize`. Restored volume `actualSize` 299896832 B (~286 MiB) matched the backup `size` 299892736 B; live `data-vault-0` Longhorn volume `actualSize` 285351936 B (~272 MiB), same order of magnitude. Vault data is barrier-encrypted; no file contents were dumped.
- Cleanup: deleted scratch namespace `vault-restore-drill`, static PV `vault-restore-drill-pv`, and throwaway Longhorn volume `vault-restore-drill`. Post-cleanup the drill namespace, PV, and Longhorn volume were all absent; the three live Vault Longhorn volumes remained `attached`/`healthy`, and live Vault pods stayed `2/2 Running` with unchanged restart counts (vault-0 1, vault-1 0, vault-2 1).

## Vault-Level Restore Outline

Vault data is seal-protected and operationally sensitive. A restored Longhorn
volume is only usable if Vault can come up with the same KMS auto-unseal model.

### Vault generate-root break-glass prerequisite

Vault 2.x authenticates `sys/generate-root/*` unless the server config opts the
endpoint family into unauthenticated handling. Keep that directive out of the
live Vault base config. Any scratch or replacement-StatefulSet recovery config
used to open a restored Raft snapshot MUST include this top-level HCL setting
before Vault starts:

```hcl
enable_unauthenticated_access = ["generate-root"]
```

Do not substitute a captured root token or short-TTL token for this requirement.
`snapshot-force` replaces the token store, and a delayed restore can happen after
any captured token has expired. The durable recovery credential is the recovery-
key quorum. With the directive present only on the isolated recovery Vault, use
the quorum to complete `sys/generate-root` and mint a fresh root there.

For a real Vault disaster, standardize on a replacement StatefulSet carrying the
recovery config before startup. Do not perform an in-place live StatefulSet edit
to temporarily enable the unauthenticated family; live base must remain hardened.

Step 156 proved this path on `vault-drill`: token-less `generate-root` completed
from the scratch recovery key, the generated scratch root read `sys/mounts`, the
generated root was revoked, and the scratch PVC was wiped and reinitialized
empty afterward. See
[ADR-0019](../decision-records/repo/0019-enable-tokenless-vault-generate-root.md).

For a scratch restore:

1. Deploy an isolated Vault instance or StatefulSet that will not receive
   production traffic.
2. Attach the restored Longhorn volume to that scratch Vault.
3. Provide the same Vault configuration shape, TLS trust, and AWS KMS
   auto-unseal credential path used by production.
4. Start Vault and confirm it auto-unseals:

   ```bash
   vault status
   ```

5. Verify Raft state, mounted secrets engines, policies, PKI roles, and the CA
   material needed for recovery.
6. Restart the scratch Vault pod once and confirm it auto-unseals again.
7. Record the backup timestamp, restored volume name, Vault version, KMS
   verification result, and gaps.

For a production restore, keep the restored Vault isolated until the owner
approves replacing the real workload. Avoid production DNS, Gateway routes, and
client automation until the restore target has been verified.

## Limitations And Intent

The Synology target is a durable, always-on appliance with RAID6 + Btrfs checksum
redundancy and NAS-side immutable snapshots — a substantial improvement over the
retired session-bound WSL target. Remaining gaps:

- NFS transport is unencrypted (AUTH_SYS, no TLS/krb5p). Mitigated by the isolated
  storage VLAN, per-host scoping, and the fact that the crown-jewel payload (Vault
  Raft) is barrier-encrypted inside the backup. Revisit if non-encrypted sensitive
  PVs are later backed up here.
- The share is not encrypted at rest (the payload already is). Same revisit trigger.
- The appliance is shared with unrelated business backups; it is not a dedicated
  backup host (mitigated by the dedicated share, quota, and scoping).
- The backup target is local only; the offsite/offline copy required for a complete
  3-2-1-1-0 posture remains future work.
- Snapshot deletion is possible by a DSM administrator outside the 7-day WORM window
  — a separate trust boundary; the setup admin credentials are rotated and never
  stored in-cluster.

These residuals are ratified in the tech-debt register as TD-0005 (offsite copy), TD-0006 (transport/at-rest crypto), and TD-0007 (NAS admin/isolation trust boundary) in [docs/tech-debt.md](../tech-debt.md).

The durable direction remains:

- 3 production copies through Longhorn replica placement where appropriate;
- 2 media/classes through cluster storage plus the Stage 1 NAS;
- 1 offsite or offline copy after the on-site target is stable and retention is
  proven, alongside the NAS-side immutable snapshots already in place.
