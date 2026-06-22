# DR Stage 1 Backup

This runbook covers the current DR Stage 1 backup lifecycle for the Talos
cluster. ADR-0014 records the decision to use a local Stage 1 backup server;
this document is the operator how-to/reference for the interim NFS-backed
implementation and the Synology migration path.

The current implementation protects Longhorn volume data by sending Longhorn
backups to an NFS export on the owner's workstation. It is intentionally
interim: the Synology NAS will replace the workstation once it is live, and the
same Longhorn backup target protocol will be kept.

## Architecture

The data path is:

1. Vault uses Longhorn volumes through the `longhorn-vault` StorageClass.
2. The `vault-daily-backup` Longhorn RecurringJob backs up matching volumes.
3. Longhorn writes backup data to `nfs://10.69.12.11:/srv/nfs/backup`.
4. The interim NFS server runs in WSL2 `Ubuntu-24.04` on the owner's
   workstation and exports `/srv/nfs/backup` to `10.69.112.0/24`.
5. The Windows Hyper-V firewall allows inbound TCP 2049 from `10.69.112.0/24`.

There are two persistence layers for the interim NFS server:

- WSL `/etc/wsl.conf` has a `[boot] command` that starts NFS whenever the
  distro starts.
- Windows Scheduled Task `WSL-NFS-Backup-Server` starts WSL at owner logon,
  starts NFS as root, and then sleeps forever to keep WSL pinned.

This means the interim server is available while the owner is logged in. It is
not a true service before owner logon. The Synology replacement removes that
session-bound limitation.

## Interim NFS Server Setup

Run the setup script as root inside the `Ubuntu-24.04` WSL distro:

```powershell
wsl.exe -d Ubuntu-24.04 -u root -- bash -lc "bash /mnt/c/Users/HellBomb/Documents/GitHub/nwarila-platform/talos-cluster/scripts/dr/nfs-interim-setup.sh"
```

The script is idempotent. It:

- installs and repairs `nfs-kernel-server`, `nfs-common`, and `rpcbind`;
- uses a temporary `policy-rc.d` exit-101 guard so package post-install scripts
  do not fail when they try to start services under WSL without systemd;
- creates `/srv/nfs/backup` with mode `1777`;
- writes `/etc/exports` as:

  ```text
  /srv/nfs/backup 10.69.112.0/24(rw,async,no_subtree_check,no_root_squash)
  ```

- mounts `nfsd` at `/proc/fs/nfsd`;
- runs `exportfs -ra`;
- starts `rpcbind`, `rpc.nfsd 8`, and `rpc.mountd`;
- installs `/usr/local/sbin/nwarila-nfs-interim-start`;
- merges this WSL boot command into `/etc/wsl.conf` without removing existing
  sections or keys:

  ```ini
  [boot]
  command = /usr/local/sbin/nwarila-nfs-interim-start
  ```

Do not run `wsl --shutdown` or `wsl --terminate` during normal setup. The boot
command takes effect on the next distro start, and shutting the distro down
would drop the currently live backup target.

## Windows Persistence Task

After the WSL setup script has run, the owner should run this file once from an
elevated Windows session:

```text
scripts\dr\Setup-NFS-Persistence.bat
```

The batch file self-elevates when needed and registers Scheduled Task
`WSL-NFS-Backup-Server` idempotently by unregistering any prior task with the
same name first.

The task:

- triggers at owner logon;
- runs with highest privileges as the interactive owner;
- runs `%WINDIR%\System32\wsl.exe -d Ubuntu-24.04 -u root -- bash -lc "..."`;
- starts `/usr/local/sbin/nwarila-nfs-interim-start` when present;
- falls back to the inline NFS start sequence if the helper is missing;
- ends the WSL command with `exec sleep infinity` to keep the distro alive;
- has no execution time limit;
- restarts every minute on failure;
- does not stop on idle end.

The batch file must print `SUCCESS` before the owner closes it.

## Firewall Rule

The owner has already applied the interim Hyper-V firewall rule from the prior
setup step. Keep the rule scoped to the Talos node subnet:

- local host: owner workstation, currently `10.69.12.11`;
- allowed remote subnet: `10.69.112.0/24`;
- protocol/port: inbound TCP 2049;
- service: NFSv4 backup target.

When the NFS endpoint moves to Synology, update the equivalent firewall rule or
NAS firewall allowlist to the same remote subnet. Do not broaden the rule to
all local networks.

## Longhorn Backup Configuration

The Longhorn Helm values define the interim target:

```yaml
defaultBackupStore:
  backupTarget: "nfs://10.69.12.11:/srv/nfs/backup"
  backupTargetCredentialSecret: ""
```

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
local operational recovery, not as the full 3-2-1 target. The long-term design
is local NAS plus a later offsite copy for disaster scenarios that include the
owner workstation or NAS.

## Health Checks

Use these checks after setup, after workstation reboot, and after Synology
migration.

On Windows, confirm the task exists:

```powershell
Get-ScheduledTask -TaskName WSL-NFS-Backup-Server
```

Inside WSL, confirm the export and NFS processes:

```bash
exportfs -v
mountpoint -q /proc/fs/nfsd
pgrep -a rpcbind
pgrep -a rpc.nfsd
pgrep -a rpc.mountd
```

In Kubernetes, confirm Longhorn sees the target as available:

```bash
kubectl -n longhorn-system get settings.longhorn.io backup-target backup-target-credential-secret
kubectl -n longhorn-system get recurringjobs.longhorn.io vault-daily-backup
```

In the Longhorn UI or API, confirm the backup target status is available and
the newest Vault backups are within the expected daily window.

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

## Vault-Level Restore Outline

Vault data is seal-protected and operationally sensitive. A restored Longhorn
volume is only usable if Vault can come up with the same KMS auto-unseal model.

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

## Synology Migration

When the Synology NAS is live, migrate Longhorn to the Synology NFS export with
the same protocol:

1. Create the Synology NFS export for Longhorn backups.
2. Restrict the Synology export and firewall to `10.69.112.0/24`.
3. Confirm a temporary pod can reach the Synology NFS endpoint on TCP 2049.
4. Update `addons/longhorn/values.yaml`:

   ```yaml
   defaultBackupStore:
     backupTarget: "nfs://<synology-ip>:/<synology-export-path>"
     backupTargetCredentialSecret: ""
   ```

5. Reconcile the Longhorn HelmRelease through Flux.
6. Confirm Longhorn reports the backup target as available.
7. Trigger or wait for the next `vault-daily-backup`.
8. Confirm a new Vault backup appears on the Synology target.
9. Retire the workstation Scheduled Task only after the Synology target is
   proven and no active restores need the workstation copy.

Expected hands-on time is about one hour if the Synology export and firewall
are ready.

## Limitations And Intent

The interim workstation NFS target is useful because it exists now and keeps
Longhorn backups off the cluster. It is still a compromise:

- WSL is session-bound, so the Scheduled Task only guarantees NFS while the
  owner is logged in.
- A workstation reboot interrupts the target until owner logon and task start.
- The workstation is not the final redundant Stage 1 appliance.
- NFS export authorization is IP-scoped, not authenticated.
- The backup target is local only; it is not yet the offsite copy required for
  a complete 3-2-1 posture.

The durable direction remains:

- 3 production copies through Longhorn replica placement where appropriate;
- 2 media/classes through cluster storage plus Stage 1 NAS backup storage;
- 1 offsite or offline copy after the Synology target is stable and retention
  is proven.