# Backup And DR Restore Drill

This runbook proves that the cluster can recover from Stage-0 and Stage-1
artifacts. It is a drill plan, not an instruction to touch production during a
docs change.

Use it for two situations:

- **Non-production drill:** restore selected snapshots into isolated Talos and
  Vault environments. This is the normal way to prove backups.
- **Production emergency:** perform the same restore classes only after owner
  approval, because etcd restore wipes control-plane state and Vault Raft
  restore overwrites Vault data.

Snapshots, manifests, tokens, kubeconfigs, talosconfigs, and Vault data are
sensitive. Keep them in `.s3/`, encrypted removable media, or the Stage-1
server. Never commit them.

## Drill Scope

A passed drill proves both recovery primitives:

1. Stage-0 material can regenerate or retrieve the Talos and Kubernetes access
   needed to rebuild the control plane.
2. An etcd snapshot can be restored with `talosctl bootstrap --recover-from`.
3. A Vault Raft snapshot can be restored into a sacrificial Vault deployment and
   unsealed through the same KMS seal path.
4. The results, checksums, versions, elapsed restore time, and gaps are recorded.

Longhorn/PV data is not proven by this runbook yet. etcd contains Longhorn
object references; it does not prove the bytes behind every PVC are recoverable.

## Required Inputs

- Stage-0: `secrets.yaml`, `age.agekey`, `talosconfig`, and kubeconfig access.
- Stage-1 or interim encrypted media:
  - one etcd snapshot (`*.db`) and its manifest
  - one Vault Raft snapshot and its manifest
- The repo revision used to generate the machine configs.
- Tooling compatible with the snapshot versions: `talosctl`, `kubectl`, and
  `vault`.
- AWS KMS/STS/Roles Anywhere reachability for Vault auto-unseal.
- A sacrificial Talos environment and a sacrificial Vault environment isolated
  from production clients.

## Universal Preflight

1. Choose snapshots whose timestamps pre-date the incident or the drill
   checkpoint.
2. Copy them to an ignored local path such as `.s3/restore/`.
3. Verify every checksum from the manifest:

   ```bash
   sha256sum -c MANIFEST.sha256
   ```

4. Record these values in the drill log:

   - snapshot UTC timestamp
   - source node or pod
   - snapshot SHA256
   - Talos, Kubernetes, and Vault versions
   - repo commit used for generated configs
   - operator or runner identity

5. Confirm the drill environment is isolated. It must not advertise production
   Vault routes, Gateway routes, DNS records, or client endpoints.
6. Confirm no command in this runbook is pointed at production unless this is an
   owner-approved emergency restore.

## etcd Restore Drill

Use a sacrificial Talos control plane whenever possible. A full-fidelity drill
uses the same Talos and Kubernetes minor versions as production and enough
network fidelity that the restored API server can start. A smaller lab may show
some restored Nodes as `NotReady`; that is acceptable only if the drill records
the limitation and still proves API, CRD, Flux, and object-state recovery.

### Steps

1. Prepare or rebuild the sacrificial control-plane nodes from Stage-0 material.
   Use generated configs from the recorded repo commit.
2. Ensure the target control-plane disks are clean. This is destructive in
   production and owner-gated there.
3. Apply the control-plane machine configs using the appropriate Talos bootstrap
   path for clean nodes.
4. Bootstrap one control-plane node from the selected snapshot:

   ```bash
   talosctl bootstrap \
     --talosconfig .s3/configs/talosconfig \
     --nodes <bootstrap-cp-ip> \
     --recover-from .s3/restore/etcd-snapshot.db
   ```

5. Wait for the API server and etcd to become reachable:

   ```bash
   talosctl --talosconfig .s3/configs/talosconfig --nodes <bootstrap-cp-ip> health
   kubectl --kubeconfig .s3/configs/kubeconfig get --raw=/readyz
   ```

6. Verify restored cluster state:

   ```bash
   kubectl --kubeconfig .s3/configs/kubeconfig get crds
   kubectl --kubeconfig .s3/configs/kubeconfig get ns
   kubectl --kubeconfig .s3/configs/kubeconfig get kustomizations.kustomize.toolkit.fluxcd.io -A
   kubectl --kubeconfig .s3/configs/kubeconfig get helmreleases.helm.toolkit.fluxcd.io -A
   kubectl --kubeconfig .s3/configs/kubeconfig -n longhorn-system get volumes.longhorn.io
   kubectl --kubeconfig .s3/configs/kubeconfig -n deploy-vault get statefulset,pvc,svc
   ```

7. Record any objects that are expected to be degraded because the lab does not
   include production workers, storage disks, DNS, or Gateway exposure.

### etcd Pass Criteria

The etcd drill passes only if:

- `talosctl bootstrap --recover-from` completes without manual data edits.
- Kubernetes `/readyz` returns success for the restored API server.
- Core CRDs, namespaces, Flux Kustomizations, HelmReleases, Vault objects, and
  Longhorn object references from the snapshot are present.
- The restored state is from the selected snapshot timestamp and not from a
  fresh bootstrap.
- Any non-ready Nodes, Pods, or Volumes are explained by deliberate lab
  differences rather than restore failure.
- The drill log records RPO, approximate RTO, snapshot SHA256, and corrective
  actions.

## Vault Raft Restore Drill

Vault Raft snapshots are seal-encrypted. Restoring the file is not enough: the
restored Vault must be able to unseal through the same AWS KMS seal path. If
KMS, STS, Roles Anywhere, the workload certificate, or the dedicated CMK are
unavailable, the restored Vault may remain sealed.

Run this against a sacrificial Vault deployment, isolated from production
clients. A restored copy contains real PKI keys and secrets. Do not expose it
through production DNS, Gateway routes, or automation that could issue real
client certificates.

### Snapshot Access Notes

The future clean capture path is an in-cluster job that talks to a Vault DNS
name present in the serving certificate, such as the
`vault-N.vault-internal.deploy-vault.svc.cluster.local` names configured in
deploy-vault, with `VAULT_CACERT` mounted from the Vault CA.

For an operator one-off over a local tunnel, the certificate SAN will not match
`127.0.0.1`:

```bash
kubectl -n deploy-vault port-forward svc/vault 8200:8200
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_SKIP_VERIFY=true
```

Use that tunnel only for the specific manual operation being performed. Do not
build scheduled automation around TLS skip-verify.

Before any real capture or restore, verify Vault policy coverage. Backup needs
read access to `sys/storage/raft/snapshot`. Restore is break-glass and may need
update access to `sys/storage/raft/snapshot` and
`sys/storage/raft/snapshot-force`.

### Steps

1. Stand up a sacrificial Vault deployment with the same storage mode, TLS CA
   trust, and AWS KMS seal configuration as production.
2. Confirm it can reach KMS/STS/Roles Anywhere and can auto-unseal:

   ```bash
   vault status
   ```

3. Point the Vault CLI at the sacrificial Vault address and CA:

   ```bash
   export VAULT_ADDR=https://<drill-vault-fqdn>:8200
   export VAULT_CACERT=<path-to-drill-vault-ca.crt>
   ```

4. Authenticate with a drill/break-glass token whose policy explicitly permits
   Raft snapshot restore.
5. Restore the selected Raft snapshot:

   ```bash
   vault operator raft snapshot restore -force .s3/restore/vault-raft.snap
   ```

6. Wait for Vault to restart or reload as required by the restore behavior, then
   verify status and Raft peers:

   ```bash
   vault status
   vault operator raft list-peers
   ```

7. Verify PKI and critical state are present without issuing production-facing
   certificates:

   ```bash
   vault secrets list
   vault list <pki-mount>/roles
   vault read <pki-mount>/cert/ca
   vault policy list
   ```

8. Restart or reschedule one sacrificial Vault pod and confirm it unseals
   through KMS without manual recovery keys.

### Vault Pass Criteria

The Vault drill passes only if:

- `vault operator raft snapshot restore -force` completes against the
  sacrificial deployment, not production.
- `vault status` reports `Sealed false` after restore and the seal path remains
  the AWS KMS model.
- `vault operator raft list-peers` shows the expected drill cluster peer state.
- PKI mounts, roles, CA/intermediate material, and critical policies are present
  from the snapshot.
- A pod restart or reschedule auto-unseals through KMS.
- No production DNS, Gateway, clients, or certificate issuance paths used the
  restored copy.
- The drill log records RPO, approximate RTO, snapshot SHA256, KMS/seal
  verification, and corrective actions.

## Production Emergency Guardrails

Production restore is not a normal drill:

- etcd restore requires clean control-plane state and may require wiping or
  reprovisioning CP nodes.
- Vault Raft restore overwrites Vault state.
- Longhorn/PV recovery may require a separate data restore that this runbook
  does not yet cover.
- The owner must approve the exact snapshot timestamp and rollback target.
- Take new emergency copies of any still-readable state before overwriting it,
  unless doing so would worsen the incident.

## Monitoring Requirements

Once capture automation exists, alert on:

- newest Vault Raft snapshot older than 90 minutes
- newest etcd snapshot older than 8 hours
- any failed snapshot upload or checksum mismatch
- Stage-1 server disk, scrub, capacity, TLS certificate, or service-health
  failures
- Vault KMS/Roles Anywhere certificate expiry, Vault PKI intermediate expiry,
  and backup-server credential/certificate expiry
- no restore drill recorded within the owner-approved interval

The alert should create a visible issue or page the owner. A failed backup job
must not silently age for days.

## Drill Record Template

For each drill, record:

```text
Date:
Operator:
Repo commit:
etcd snapshot:
etcd snapshot SHA256:
Vault snapshot:
Vault snapshot SHA256:
Stage-0 source:
Stage-1/interim source:
Talos/Kubernetes/Vault versions:
etcd result:
Vault result:
RPO observed:
RTO observed:
Gaps/corrective actions:
Next drill due:
```
