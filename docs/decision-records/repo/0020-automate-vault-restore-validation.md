# ADR-0020: Automate Vault Restore Validation

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-08                              |
| Authors        | Nick Warila (@NWarila), Codex implementation support |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | S0 generate-root drill, DR roadmap, ADR-0009, ADR-0014, ADR-0019 |
| Informed       | future platform operators and reviewers |
| Reversibility  | Medium                                  |
| Review-by      | 2026-07-15                              |

## TL;DR

Automate Vault restore validation as a recurring, unattended, self-verifying
disaster-recovery control. The validator should restore the newest eligible
Vault backup into an isolated scratch workload, recover access with the escrowed
recovery-key quorum, prove the restored data is usable, record recovery time,
emit tamper-evident results, and destroy the scratch environment.

This ADR authorizes the staged design direction. It does not approve live Vault
changes, live generate-root, production restore, or any cluster mutation beyond
future narrowly scoped implementation PRs.

## Context and Problem Statement

ADR-0014 requires restore drills before backups are accepted as working. The
current Stage-1 path has proven manual Longhorn restore from the interim NFS
target, including bbolt shape checks and scratch cleanup. ADR-0019 then proved
the missing Vault-specific recovery primitive: an isolated recovery workload can
use `enable_unauthenticated_access = ["generate-root"]` plus the recovery-key
quorum to mint a fresh root token after a restored Raft snapshot replaces the
token store.

The remaining deficiency is that restore validation is still human-triggered and
not yet a durable control. A backup system that only captures snapshots can fail
silently when storage, KMS, credentials, manifests, Vault version compatibility,
or restore automation drift. The repository needs a routine validator that proves
that the latest backup can be restored without touching live Vault.

The owner has confirmed that all three cluster recovery keys are backed up. The
as-built Vault recovery quorum is two of three recovery shares.

## Decision

Adopt an automated Vault restore validator as the next DR capability, staged on
the existing interim NFS Stage-1 backup target before adding offsite Object-Lock
or Synology-backed immutability.

The validator will:

1. Select the newest eligible Vault backup and its manifest from the Stage-1
   target.
2. Verify backup metadata before restore, including size, expected source volume,
   timestamp, checksum, and later KMS-backed signature when the signed-result
   phase lands.
3. Restore into an isolated scratch namespace and workload only. Live Vault
   StatefulSets, PVCs, services, and config must not be reused, patched, rolled,
   or execed into by the validator.
4. Start scratch Vault with a recovery config that includes
   `enable_unauthenticated_access = ["generate-root"]`, as allowed by ADR-0019.
5. Complete tokenless generate-root with exactly the required recovery-key
   quorum for the as-built cluster, currently two of three recovery shares.
6. Use the generated root only inside the validation run to prove representative
   restored data is decryptable and operationally shaped. The first implementation
   should check at least Vault health, mount table access, selected KV-v2 paths
   such as `secret/`, PKI metadata where available, and Raft or bbolt structural
   evidence that the restore is not merely a mounted file tree.
7. Revoke the generated root token or tear down the restored Vault before any
   token can escape the run boundary. The token and raw recovery shares must
   never be written to git, logs, Kubernetes Events, result artifacts, or durable
   volumes.
8. Emit a PASS or FAIL result that records backup identity, manifest identity,
   git SHA, tool versions, Vault version, scratch resource names, checks
   performed, elapsed restore time, cleanup evidence, and failure reason when
   applicable.
9. Destroy the scratch namespace, workloads, PVCs, Longhorn restored volume, and
   any temporary credentials, then prove those resources are absent.

The validator must use net-new identities rather than reusing live Vault workload
identity:

- a Kubernetes service account for orchestration, limited to the future scratch
  validation namespace and the minimum Longhorn/Kubernetes resources needed for
  restore and cleanup;
- a separate credential path for backup, KMS, SSM, and Roles Anywhere reads as
  needed by scratch validation;
- a split generate-root path where the component that handles raw recovery shares
  is isolated from the component that performs ordinary Vault sampling whenever
  practical.

The interim NFS target remains acceptable for this phase. NFS provides restore
availability and tamper detection when paired with manifests, checksums, and
signed results. It does not provide tamper prevention. Immutable offsite storage
remains a later phase and should have its own ADR or an explicit update to
ADR-0014 before this repository introduces a new AWS/S3 operational backup path.

## Consequences

### Positive

- Turns Vault backup validation from an occasional manual drill into a recurring
  control with objective PASS/FAIL evidence.
- Exercises the real delayed-restore credential path: recovery-key quorum to new
  root on an isolated restored Vault, not a preexisting token.
- Keeps live Vault hardened because tokenless generate-root remains confined to
  scratch and recovery configs.
- Creates a natural foundation for signed DR results, staleness alerting, and
  future immutable/offsite backup verification.

### Negative

- Automating recovery-key quorum use increases sensitivity. The implementation
  must treat recovery shares and generated root material as crown-jewel secrets.
- The first validator can only prove what the interim NFS target can supply. It
  detects many failure classes but does not prevent source backup tampering.
- Longhorn restore, Vault startup, KMS unseal, and generate-root sequencing make
  the controller more complex than a file-shape checker.

### Neutral

- This decision does not change live Vault configuration.
- This decision does not supersede ADR-0014's current Stage-1 local backup
  target or its constraint against making AWS the operational snapshot store.
- This decision does not require the retired workstation restore script to be
  reused. Existing manual drill artifacts are behavioral evidence, not production
  automation source.

## Alternatives Considered

1. Keep manual restore drills only.

   Rejected. Manual drills are valuable, but they do not provide routine
   staleness detection or early warning when restore dependencies drift.

2. Build immutable offsite storage before automation.

   Deferred. Immutability is important, but the repository already has an
   interim Stage-1 target and a proven manual restore path. Automating restore
   validation now improves the live control surface while the final backup
   appliance and offsite design are still pending.

3. Reuse live Vault tokens or live Vault Kubernetes auth for validation.

   Rejected. Snapshot restore replaces the token store, and validation must not
   depend on credentials that may disappear in the disaster scenario being
   tested. The validator should also avoid creating a path from scratch
   validation into live Vault.

4. Enable `generate-root` unauthenticated on live Vault.

   Rejected by ADR-0019. The recovery surface belongs in scratch or replacement
   recovery configs, not the production Vault base.

5. Treat bbolt file-shape checks as sufficient.

   Rejected. File-shape checks prove that a restore is not empty or obviously
   malformed, but they do not prove Vault can unseal, decrypt, and serve the
   restored logical data.

## Implementation Sequence

1. Define validator identities, namespaces, RBAC, and secret boundaries.
2. Add a restore driver that creates scratch Longhorn restore resources from the
   latest eligible Vault backup and refuses to touch live `data-vault-*`
   resources.
3. Add a scratch Vault recovery driver with the ADR-0019 recovery config.
4. Add the split generate-root flow for the two-of-three recovery quorum.
5. Add Vault sampling checks that prove representative decryptability without
   dumping secret values.
6. Add fail-closed cleanup and post-cleanup absence checks.
7. Add signed or otherwise tamper-evident PASS/FAIL result artifacts and
   staleness alerting.
8. Schedule the validator only after the one-shot driver passes under manual
   owner supervision.

Each step should land in a separate small PR or tightly related PR group with
focused validation evidence.

### Implementation Notes

Slice 2 is implemented as a suspended `dr-restore-driver` CronJob in
`clusters/talos-cluster/apps/vault-restore-validator`. The slice restores the
newest eligible Vault Longhorn backup into the fixed scratch volume
`dr-validate-vault-restore`, performs only Longhorn metadata and size checks,
cleans up the scratch volume, and records a non-secret result ConfigMap.

The slice uses two separate controls for Longhorn Volume mutation. RBAC scopes
`update`, `patch`, and `delete` on `volumes.longhorn.io` to the fixed scratch
name. Kubernetes RBAC cannot scope `create` by name, so the fail-closed create
control is the native `ValidatingAdmissionPolicy`
`dr-orchestrator-longhorn-volume-allowlist`, which is scoped by
`matchConditions` to `system:serviceaccount:dr-validate:dr-orchestrator` and
allows only `dr-validate-vault-restore`. The earlier Kyverno
`protect-live-vault-longhorn-volume` denylist was replaced because a
denylist-backed external webhook with fail-open behavior is not an adequate
primary create control for this invariant.

The CronJob ships with `spec.suspend: true` and an inert Feb-31 schedule
placeholder. Scratch Vault, recovery shares, tokenless generate-root,
`enable_unauthenticated_access`, Vault data sampling, signed results, and any
automatic schedule remain deferred to later slices.

Known limitation: the scratch restore Volume currently has no Longhorn node or
disk placement constraint. A restore run could place the scratch Volume on a
`vault`-tagged disk and pressure live Vault replicas. A non-vault placement
constraint is a prerequisite before enabling the scheduling slice.

## Verification

This ADR is confirmed when:

1. The ADR and index entry are reviewed in a documentation-only PR.
2. The first implementation PR demonstrates, in CI or captured manual evidence,
   that the validator refuses to operate on live Vault resources.
3. The first successful validator run records backup identity, checksums or
   manifest identity, git SHA, Vault version, elapsed restore time, checks
   performed, and cleanup proof.
4. A negative-path test proves that recovery shares and generated root material
   are not printed to logs or persisted in result artifacts.
5. A stale-backup or failed-restore condition produces an explicit FAIL result
   and does not leave scratch resources behind.

## Assumptions

1. The cluster remains sealed through the AWS KMS auto-unseal model recorded in
   ADR-0012 and the imported Vault ADRs.
2. The current recovery quorum remains two of three shares unless a future ADR
   or accepted correction changes the escrow model.
3. The interim NFS target remains reachable long enough to build and validate
   the first automation phase.

## Out of Scope

- Revoking any still-live initial root token.
- Running generate-root against live Vault.
- Performing production restore.
- Changing Talos node recovery, etcd restore, Longhorn global backup settings,
  or Synology/Object-Lock migration.
- Implementing Keycloak, application-level restore validation, or tenant
  workload restore validation.

## Related

- [ADR-0012](0012-vault-kms-auto-unseal-credential-delivery.md) records the
  Vault KMS auto-unseal credential model.
- [ADR-0014](0014-use-stage-1-local-backup-server-for-dr.md) records the Stage-1
  local backup and restore-drill requirement.
- [ADR-0019](0019-enable-tokenless-vault-generate-root.md) confines tokenless
  generate-root to scratch and recovery configs.
- [Imported Vault ADR-0009](vault/0009-recovery-escrow-and-bootstrap-ceremony.md)
  records recovery-key escrow and generate-root break-glass intent.
- [DR Stage 1 backup runbook](../../runbooks/dr-stage1-backup.md) records the
  current interim NFS backup target and manual restore-drill evidence.

## Compliance Notes

| Framework             | Control | Relevance |
| --------------------- | ------- | --------- |
| NIST SP 800-53 Rev. 5 | CP-9    | Validates backup integrity and recoverability rather than only capturing backups. |
| NIST SP 800-53 Rev. 5 | CP-10   | Exercises restoration into an isolated environment with explicit pass/fail criteria. |
| NIST SP 800-53 Rev. 5 | IA-5    | Keeps generated root and recovery shares bounded to a controlled recovery workflow. |
| NIST SP 800-53 Rev. 5 | AU-12   | Produces audit-ready validation evidence for each run. |
| NIST SP 800-53 Rev. 5 | SI-4    | Supports alerting on stale, failed, or incomplete restore-validation runs. |
