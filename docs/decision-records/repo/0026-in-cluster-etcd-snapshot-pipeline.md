# ADR-0026: In-Cluster etcd Snapshot Pipeline to Stage-1

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-11                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | First restore drill against a snapshot produced by this pipeline |

## TL;DR

etcd snapshots are captured **in-cluster** by a daily Flux-reconciled CronJob
(`clusters/talos-cluster/apps/dr-etcd-backup/`): a restricted pod saves a
snapshot over apid with a role-scoped `os:etcd:backup` talosconfig, whole-file
encrypts it to a dedicated age recipient whose private key is escrowed
off-cluster, and lands it on a Longhorn volume that the `etcd-daily-backup`
RecurringJob ships to the Stage-1 Synology target. This completes the etcd leg
of [ADR-0014](0014-use-stage-1-local-backup-server-for-dr.md) and retires the
never-successful GitHub Actions S3 workflow from
[ADR-0006](0006-etcd-snapshot-automation.md) (workflow and script deleted).

## Context and Problem Statement

ADR-0006 built etcd snapshot automation as a scheduled GitHub Actions workflow
uploading to S3 with KMS. It never ran successfully: scheduled use was disabled
in 2026-06 when ADR-0014 retargeted operational snapshots to a Stage-1 local
backup server, the `self-hosted` runner it requires does not exist
([no-self-hosted-runners posture](0016-isolated-arc-runner-for-repo-sync.md)
notwithstanding — the repo-sync runner is deliberately single-purpose), and the
static AWS operator key it depended on is dead. Meanwhile the Stage-1 server
now exists (Synology `TCNHQ-BKUP01`, ADR-0021), Longhorn ships volumes to it
daily, and the Vault leg is live. etcd remained the gap: the cluster's only
recovery primitive for Kubernetes state had zero fresh artifacts.

Everything here must also satisfy the operating model: capture must be
Flux-reconciled (everything in-band), and every capability must be scoped to
exactly what it needs.

### The network-model correction this design rests on

The first design iteration assumed pods cannot reach the Talos management API
(apid, tcp/50000) because the `ingress-apid` node firewall
(`cluster/patches/firewall.yaml`) admits only the operator and node subnets,
deliberately excluding the pod CIDR — and therefore called for a hostNetwork
pod on a control-plane node inside a PSA-privileged namespace.

Live evidence disproved the premise: Cilium runs with
`enable-ipv4-masquerade: true` (tunnel mode), so pod egress to any node IP is
**masqueraded to the sending node's own IP** and the firewall admits it. The
`talos-drift-readonly` CronJob — a plain restricted pod — queries apid on all
six nodes every hour this way, including its own host node.

The corrected model, now the documented basis for anything touching apid:

- The Talos node firewall filters **external** sources (other VLANs, arbitrary
  LAN hosts). It does not constrain in-cluster pods, whose traffic reaches
  apid with a node-subnet source address.
- What actually separates pods from apid is (1) the **per-namespace
  default-deny egress NetworkPolicy** posture, under which apid access must be
  granted by an explicit scoped allow, and (2) **apid's own mTLS + Talos RBAC**
  — without a client certificate carrying an authorized role, reachability is
  not access.
- A hostNetwork pod would be strictly *worse* here: host endpoints are exempt
  from namespaced network policy, removing layer (1) entirely.

## Decision Drivers

1. **Close the etcd DR gap** — the cluster carries platform state (Flux, Vault
   integration, Longhorn metadata, tenancy) whose only home is etcd.
2. **Everything in-band** — capture runs under Flux, not from an operator
   workstation or an external CI system.
3. **Least privilege** — the snapshot credential must not be able to do
   anything but snapshot; the pod must not hold Kubernetes API access; the
   namespace must not grant more network than apid.
4. **Ciphertext on the shared target** — the Synology is intentionally
   unencrypted and shared with other appliances. Kubernetes Secrets inside a
   snapshot are already ciphertext (kube-apiserver encryption-at-rest with the
   secretbox key escrowed off-Synology), but all non-Secret etcd data
   (ConfigMaps, workload specs, RBAC, topology) is plaintext, and the old S3
   path's KMS layer is gone. Whole-file encryption restores defense-in-depth.
5. **A dead cluster must be able to decrypt its own snapshots** — the decrypt
   key cannot live only inside the cluster it is meant to resurrect.

## Considered Options

1. **In-cluster Flux CronJob, restricted pod + scoped egress policy** (chosen).
2. **In-cluster CronJob with hostNetwork on a control-plane node** — the
   original locked design.
3. **ARC runner workflow retargeted to Stage-1** — reuse the GitHub Actions
   script on the in-cluster runner fleet.
4. **Keep the ADR-0006 S3 workflow** on a future self-hosted runner.

## Decision Outcome

Chosen option: **Option 1.**

- **Namespace** `dr-etcd-backup`: PSA `restricted`, default-deny
  NetworkPolicy, and one scoped `CiliumNetworkPolicy` granting the snapshot
  pod egress to the control-plane apid (tcp/50000) only, via the
  `kube-apiserver` Cilium entity (no DNS — talosctl targets literal IPs;
  encryption is offline). The entity — not a CIDR list — is required: control-
  plane node IPs carry Cilium's reserved `kube-apiserver` identity, and a plain
  CIDR rule does not match reserved-identity traffic under this cluster's
  default identity config, so a `toCIDRSet` of the CP IPs silently matches
  nothing and the snapshot times out. The `kube-apiserver` identity resolves to
  exactly the three control-plane nodes (the etcd hosts).
- **Credential**: `talosctl config new --roles os:etcd:backup --crt-ttl 17520h`
  (expires **2028-07-10**), SOPS-encrypted in git, decrypted by Flux. Verified
  live: it takes a real snapshot and is `PermissionDenied` for machine-config
  reads and node lifecycle operations.
- **CronJob** (03:00 UTC daily, two containers, the talos-drift pattern):
  a `ghcr.io/siderolabs/talosctl` init container saves `/work/etcd.db`; the
  official `ghcr.io/getsops/sops` image (sops embeds age) encrypts it
  whole-file to the age recipient, writes `etcd-<stamp>.db.sops.json` onto the
  `etcd-snapshots` PVC (`longhorn-etcd-snapshot` StorageClass), prunes to 14
  local dailies, and refuses snapshots smaller than 10 MB. Both images are
  digest-pinned.
- **Shipping**: the StorageClass's `recurringJobSelector` binds the
  `etcd-daily-backup` RecurringJob (03:47 UTC, retain 14) to the volume;
  Longhorn's `allowRecurringJobWhileVolumeDetached: true` covers the
  mostly-detached volume. Both guard layers of the restore-validator boundary
  allowlist exactly the two backup RecurringJobs by name and pin
  `spec.task: backup`.
- **Key management**: a dedicated age keypair, generated 2026-07-11. The
  cluster holds only the **public** recipient (an environment value on the
  CronJob) — it cannot decrypt its own archives. The private key is escrowed
  twice: raw to Stage-0 S3 (staged at `.s3/secrets/etcd-snapshot-age.agekey`),
  and repo-key-encrypted at `docs/dr-escrow/etcd-snapshot-age-key.sops.yaml`
  (`kind: EscrowedAgeKey`, deliberately not applyable and never referenced by
  a kustomization). The dead-cluster decrypt path is documented in that file.
- **Retirement**: `.github/workflows/etcd-snapshot.yaml` and
  `scripts/etcd-snapshot.sh` are deleted (0 lifetime successes; dead runner
  and dead credential), along with their workflow-health exception.

### Restore path (unchanged in kind, new in detail)

1. Obtain the age private key (S3 Stage-0, or `sops -d` the escrow file with
   the Stage-0 repo age key).
2. Pull the newest `etcd-<stamp>.db.sops.json` from the Synology Longhorn
   backup (restore the volume, or read the live PVC if the cluster is up).
3. `SOPS_AGE_KEY_FILE=<key> sops -d --input-type json --output-type binary
   <file> > etcd.db`
4. `talosctl bootstrap --recover-from=etcd.db` per the DR runbook.

## Pros and Cons of the Options

### Option 1: restricted pod + scoped egress (chosen)

- **Good, because** the snapshot pod sits *under* namespaced network policy —
  a single-rule allow-list — instead of being exempt from it.
- **Good, because** every layer is the minimum: snapshot-only Talos role, no
  ServiceAccount token, no DNS, restricted PSA like every other namespace.
- **Good, because** the whole pipeline is Flux-owned; a bad change reverts by
  Git revert.
- **Bad, because** it depends on the masquerade behavior for apid
  reachability; if masquerade or the firewall model changes, the CNP-allowed
  path must be revisited (the drift detector exercises the same path hourly
  and would fail loudly alongside it).

### Option 2: hostNetwork on a control-plane node

- **Bad, because** its motivating premise was false (see the network-model
  correction) — pods already reach apid without host networking.
- **Bad, because** it required a PSA-privileged namespace and produced a pod
  outside namespaced network policy.
- **Good, because** it would have used the loopback apid path with no
  dependency on masquerade behavior. Not worth the posture cost.

### Option 3: ARC runner workflow

- **Bad, because** it hands cluster-state read capability (etcd snapshots
  embed everything) to the CI runner fleet, whose namespaces are deliberately
  denied apid egress.
- **Bad, because** the runner fleet is single-purpose by design (repo-sync,
  ADR-0016); broadening it re-opens the boundary that design closed.

### Option 4: keep the S3 workflow

- **Bad, because** every dependency is dead: no self-hosted runner, revoked
  static AWS key, and a storage target ADR-0014 explicitly rejected for
  operational snapshots. Zero successful runs ever.

## Confirmation

1. `kustomize` renders and the Flux root applies `apps/dr-etcd-backup/`
   (namespace, SA, netpols, PVC, SOPS talosconfig, script ConfigMap, CronJob).
2. The restore-validator boundary guard and the Kyverno
   `no-unapproved-longhorn-recurringjob` rule pin the approved RecurringJob
   set and `spec.task: backup` (regression selftest covers both directions).
3. Nightly proof: a fresh `etcd-<stamp>.db.sops.json` on the PVC and a
   completed `etcd-daily-backup` Longhorn backup on the Synology.
4. Decrypt proof: performed 2026-07-11 with the real keypair (byte-identical
   round-trip). MUST be repeated as part of the first restore drill.
5. Rotation: the scoped talosconfig expires **2028-07-10**; re-mint and
   re-encrypt before then (silent expiry would fail the Job visibly, but
   monitoring for CronJob failure is a tracked gap — see Negative).

## Consequences

### Positive

- The last missing Stage-1 leg is live: etcd, Vault, and PV data all reach the
  Synology on a daily cadence with bounded retention.
- Snapshot artifacts on the shared target are ciphertext; the cluster cannot
  decrypt its own archives; a Synology-side reader gets nothing.
- The corrected pod→apid network model is now written down where the next
  apid-adjacent design will find it.

### Negative

- No alerting yet on CronJob failure — a silently failing snapshot job would
  only be caught by inspection until the workflow-health lane (SM4) grows an
  in-cluster equivalent. Tracked.
- The talosctl image digest is pinned in two places (talos-drift and this
  CronJob) and must move in lockstep with Talos upgrades.
- Restore remains **undrilled** end-to-end for this pipeline's artifacts; the
  Review-by field gates on the first drill.

### Neutral

- ~110 MB snapshot → ~147 MB ciphertext daily; 14 local + 14 Synology copies
  is a few GB — negligible on both tiers.
- The GitHub Actions surface shrinks by one workflow with 0 lifetime
  successes.

## Assumptions

1. Cilium masquerade behavior (pod→node traffic SNAT'd to node IP) persists
   across Cilium upgrades; the talos-drift hourly job is a continuous canary.
2. `talosctl etcd snapshot` output stays restorable via
   `talosctl bootstrap --recover-from` within the N/N+1 Talos version window.
3. Longhorn's detached-volume recurring backups
   (`allowRecurringJobWhileVolumeDetached`) keep working across Longhorn
   upgrades — the 1.12 upgrade (#247) should re-verify.

## Supersedes

Completes the etcd leg of [ADR-0014](0014-use-stage-1-local-backup-server-for-dr.md).
Retires the implementation half of [ADR-0006](0006-etcd-snapshot-automation.md)
(already superseded by ADR-0014); its S3-era workflow and script are deleted.

## Related ADRs

- [ADR-0014](0014-use-stage-1-local-backup-server-for-dr.md) — the Stage-1
  architecture this fulfills.
- [ADR-0021](0021-synology-nfs-backup-target-for-longhorn.md) — the backup
  target.
- [ADR-0022](0022-longhorn-under-flux-gitops.md) — Longhorn under Flux, which
  makes the RecurringJob/StorageClass pieces declarative.
- [ADR-0024](0024-two-layer-enforcement-of-restore-validator-boundary.md) —
  the guard layers that allowlist this pipeline's RecurringJob.
- [ADR-0016](0016-isolated-arc-runner-for-repo-sync.md) — the single-purpose
  runner posture that rules out Option 3.

## Compliance Notes

| Framework              | Control / Practice ID                      | Potential Evidence Contribution                                                                 |
| ---------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5  | CP-9 (System Backup)                       | Daily encrypted etcd snapshots to off-host storage; RPO ≤ 24h; dual-tier retention.              |
| NIST SP 800-53 Rev. 5  | CP-10 (System Recovery and Reconstitution) | Documented decrypt + `talosctl bootstrap --recover-from` path; key escrowed off-cluster.        |
| NIST SP 800-53 Rev. 5  | SC-28 (Protection of Information at Rest)  | Whole-file age encryption; cluster holds encrypt-only material; target holds ciphertext only.   |
| NIST SP 800-53 Rev. 5  | AC-6 (Least Privilege)                     | Snapshot-only Talos role; no SA token; single-rule egress; restricted PSA.                       |
