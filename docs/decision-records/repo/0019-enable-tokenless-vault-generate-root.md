# ADR-0019: Enable token-less Vault generate-root for recovery-key break-glass

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-01                              |
| Authors        | Nick Warila (@NWarila), Codex implementation support |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | Step 155 restore finding, Step 156 scratch proof, HashiCorp Vault 2.x configuration docs, Vault v2.0.1 source |
| Informed       | future platform operators and reviewers |
| Reversibility  | High                                    |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Enable Vault 2.x `enable_unauthenticated_access = ["generate-root"]` in both
production Vault config and the isolated `vault-drill` scratch config. Vault 2.x
gates `sys/generate-root/*` by default; a restored Raft snapshot replaces the
token store, so recovery cannot depend on any token captured before the restore.
The durable credential is the escrowed recovery-key quorum, and generate-root
must remain reachable without a token for that quorum to mint a new root during
break-glass recovery.

This does not expose a root token by itself. An unauthenticated caller can start
or cancel a generate-root attempt and submit shares, but cannot complete the flow
without the recovery-key quorum. The accepted exposure is a bounded denial-of-
service surface, mitigated by Vault network isolation and owner-gated
port-forward access.

## Context and Problem Statement

The Step 155 restore drill proved the mechanical restore path but exposed a real
recovery failure: `sys/storage/raft/snapshot-force` replaces Vault storage,
including the token store. The scratch Vault's init root token died after the
restore, and the restored secret could not be read.

Using a short-lived or snapshot-captured token is not a recovery design. Tokens
expire on wall-clock time and can be invalidated by the restored token store. A
real delayed restore might happen days after the snapshot was taken. The only
credential intended to survive that delay is the recovery-key quorum escrowed
outside Vault.

On the running Vault build, `sys/generate-root/*` is authenticated unless the
server config opts that endpoint family back into unauthenticated handling. The
running binary was verified as:

- `Vault v2.0.1 (1a56927a170e2c67fa60a71158a3607d072a58a7)`, built
  `2026-05-19T17:20:48Z`.
- Image digest:
  `ghcr.io/nwarila-platform/ubi9-hashicorp-vault@sha256:f4c4422b5a8ec5a56db67b937b429e655e5fd73e2c7c9a308e1636520fb5f244`.

Directive verification was performed against the running binary, HashiCorp
Vault 2.x docs, and source at the exact running commit:

- The Vault 2.x configuration docs define top-level
  `enable_unauthenticated_access` as a string array and list `"generate-root"`
  as a supported endpoint family.
- `command/server/config.go` maps the top-level HCL key to
  `EnableUnauthenticatedAccess []string`.
- `vault/core.go` accepts only `"rekey"`, `"generate-root"`, and
  `"generate-operation-token"` into the runtime booleans.
- `http/handler.go` registers unauthenticated handlers for
  `/v1/sys/generate-root/attempt` and `/v1/sys/generate-root/update` only when
  the `generate-root` family is enabled.
- `http/sys_generate_root_test.go` asserts that no-token generate-root attempt
  and update return 403 without the setting and succeed with
  `EnableUnauthenticatedAccess = []string{"generate-root"}`.

## Decision

Add the following top-level Vault HCL setting to both the scratch restore-drill
config and live Vault config:

```hcl
enable_unauthenticated_access = ["generate-root"]
```

This setting is part of the recovery baseline. Any recovery-time Vault config,
replacement StatefulSet, or scratch restore harness that may need to recover a
restored Raft snapshot must carry the same directive before the restored Vault is
started. Otherwise, a token-less restored Vault may be sealed open but still
operationally inaccessible.

The production rollout is owner-gated through the normal GitOps merge path. The
post-merge verification must restart Vault in a controlled rolling manner and
verify every pod re-unseals through KMS, Raft still has three peers and one
leader, all pods are `2/2 Ready`, and existing auth still works. Live directive
verification is non-mutating only: start `sys/generate-root/attempt` with no
token, confirm it is not 403 and returns a nonce, then immediately cancel the
attempt. No recovery share is ever supplied to live as part of verification.

## Consequences

### Positive

- A restored Vault whose token store has been replaced can still mint a fresh
  root token from the recovery-key quorum.
- The restore drill now proves the real delayed-recovery credential path instead
  of relying on a token that may not exist when disaster recovery happens.
- The scratch harness permanently carries the same recovery-critical config as
  production, preventing false-positive restore drills.

### Negative

- Unauthenticated clients that can reach Vault can start or cancel a generate-
  root attempt. That is a denial-of-service surface for the break-glass workflow
  because concurrent attempts can interfere with operators until cancelled.
- The setting is easy to forget in ad hoc recovery configs. Omitting it can make
  an otherwise successfully restored Vault inaccessible.

### Neutral

- The setting does not let an unauthenticated caller mint a root token without
  the recovery-key quorum.
- Production Vault remains internal-only behind Kubernetes NetworkPolicy,
  service scoping, and operator-controlled port-forward paths. No Gateway or
  public exposure is introduced by this decision.
- The setting can be removed and Vault restarted if a future Vault version
  changes the recovery endpoint model or if the owner chooses a different
  break-glass design.

## Alternatives Considered

1. Keep generate-root authenticated and rely on a captured token.

   Rejected. Snapshot restore replaces the token store, and token TTLs expire on
   wall-clock time. This can pass a same-day drill while failing the real delayed
   disaster-recovery scenario.

2. Enable unauthenticated `rekey` or `generate-operation-token` too.

   Rejected. Step 156 only needs standard `generate-root`. Widening the
   unauthenticated family list would add DoS surface without solving the restore
   gate.

3. Use Vault recovery mode and raw storage manipulation.

   Rejected for this recovery path. Recovery mode is a last-resort storage
   surgery tool, not the ordinary restored-Vault access path. The desired
   operator workflow is recovery-key quorum to new root, then normal Vault APIs.

4. Defer the directive and document the limitation.

   Rejected. Step 155 already proved the limitation blocks real recovery. A
   documented dead end is not an acceptable backup posture.

## Verification

Step 156 verified the directive before any live config edit:

1. Running binary: `Vault v2.0.1`, commit
   `1a56927a170e2c67fa60a71158a3607d072a58a7`.
2. Documentation/source gate: top-level
   `enable_unauthenticated_access = ["generate-root"]` is the verified syntax
   and endpoint-family value for this build.
3. Scratch proof: the isolated `vault-drill` config was updated first. An empty
   scratch Vault initialized with `recovery_shares=1` and
   `recovery_threshold=1`, auto-unsealed with AWS KMS, and had one Raft peer.
4. Scratch token-less proof: `POST sys/generate-root/attempt` without a token
   returned not-403, the scratch recovery key completed
   `sys/generate-root/update`, the decoded generated root successfully performed
   token lookup and `sys/mounts`, and the generated root was revoked.
5. Scratch cleanup: the scratch StatefulSet and PVC were deleted, recreated, and
   reinitialized empty. Final verification showed one Raft peer and only Vault
   2.0.1 default mounts: `agent-registry/`, `cubbyhole/`, `identity/`, and
   `sys/`.
6. Network isolation was checked before and after the wipe/reinit: live Vault
   DNS was blocked, AWS KMS DNS resolved, and TCP to the live Vault ClusterIP was
   blocked.

Live rollout verification is intentionally deferred until the owner merges and
lets GitOps reconcile the production config. The required post-merge evidence is
recorded in the runbook and the Step 156 report.

## Related

- [ADR-0014](0014-use-stage-1-local-backup-server-for-dr.md) - requires Vault
  restore drills with pass criteria.
- [ADR-0012](0012-vault-kms-auto-unseal-credential-delivery.md) - records the
  KMS auto-unseal and credential delivery model used by restored Vault.
- [ADR-0017](0017-fold-vault-into-talos-cluster-as-a-platform-service.md) -
  records the production Vault ownership path in this repository.
- [Imported Vault ADR-0009](vault/0009-recovery-escrow-and-bootstrap-ceremony.md)
  - records recovery-key escrow and generate-root break-glass intent.
- HashiCorp Vault docs:
  <https://developer.hashicorp.com/vault/docs/configuration#enable_unauthenticated_access>.
- Vault v2.0.1 source:
  <https://github.com/hashicorp/vault/tree/1a56927a170e2c67fa60a71158a3607d072a58a7>.

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | CP-10 | Preserves a viable system recovery path when Vault tokens are unavailable after restore. |
| NIST SP 800-53 Rev. 5 | IA-5 | Keeps root-token creation gated by the recovery-key quorum instead of stored bearer tokens. |
| NIST SP 800-53 Rev. 5 | SC-7 | Accepts the unauthenticated endpoint only within Vault's internal network boundary and operator port-forward model. |
| NIST SP 800-53 Rev. 5 | CM-2 | Records the recovery-critical Vault configuration baseline in source-controlled ADR and runbook text. |