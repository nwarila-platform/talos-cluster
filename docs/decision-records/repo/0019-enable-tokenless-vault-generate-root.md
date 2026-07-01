# ADR-0019: Keep token-less Vault generate-root in recovery configs only

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

Keep Vault 2.x `enable_unauthenticated_access = ["generate-root"]` out of the
production Vault base config. Carry it only in isolated scratch or recovery
configs, including `vault-drill` and any replacement StatefulSet recovery config
used to open a restored Raft snapshot.

Vault 2.x gates `sys/generate-root/*` by default. A restored Raft snapshot
replaces the token store, so recovery cannot depend on any token captured before
the restore. The durable credential is the escrowed recovery-key quorum, and the
recovery Vault must let that quorum reach `generate-root` without a preexisting
token. The automated disaster-recovery pipeline can apply that recovery config
every run, so live Vault does not need a standing unauthenticated endpoint
family.

This setting does not expose a root token by itself. An unauthenticated caller
can start or cancel a generate-root attempt and submit shares, but cannot
complete the flow without the recovery-key quorum. That is still a bounded
denial-of-service surface, so defense-in-depth keeps it off the live service and
confines it to isolated recovery workloads.

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

Set placement to scratch/recovery-config-only.

The following top-level Vault HCL setting is allowed in the isolated restore
harness at `clusters/talos-cluster/apps/vault/restore-drill/vault-drill.hcl` and
in future replacement StatefulSet recovery configs that are deployed only for a
specific disaster-recovery run:

```hcl
enable_unauthenticated_access = ["generate-root"]
```

The setting is not allowed in `clusters/talos-cluster/apps/vault/base/vault.hcl`
or in the rendered live Vault ConfigMap. The live base must stay hardened. A
monitored invariant now enforces that boundary through both source-controlled
Kyverno policy and CI validation of the rendered live Vault ConfigMap.

Break-glass recovery standardizes on a replacement StatefulSet path: bring up a
fresh isolated Vault workload with the recovery config already present, restore
the snapshot there, let it auto-unseal through the KMS seal path, and use the
recovery-key quorum to complete `generate-root` on that recovery workload. Do
not depend on an in-place live StatefulSet edit that temporarily enables the
unauthenticated family. A real disaster is exactly when an operator is most
likely to forget a cleanup step; the safer invariant is that live base never
carries the directive.

## Consequences

### Positive

- Live Vault has no standing unauthenticated `generate-root` endpoint family,
  reducing the production attack and denial-of-service surface.
- The restore drill still proves the real delayed-recovery credential path
  instead of relying on a token that may not exist when disaster recovery
  happens.
- The recovery directive lives where automation can apply it every run: the
  scratch or replacement StatefulSet recovery config.
- CI and Kyverno guard against accidentally reintroducing the directive to the
  rendered live Vault ConfigMap.

### Negative

- Recovery automation must reliably apply the recovery config before starting a
  restored Vault. Omitting the directive from that recovery config can make an
  otherwise successfully restored Vault inaccessible.
- The replacement StatefulSet path is slightly more explicit than editing the
  existing live StatefulSet, but that explicitness is the safety property.

### Neutral

- The setting does not let an unauthenticated caller mint a root token without
  the recovery-key quorum.
- Production Vault remains internal-only behind Kubernetes NetworkPolicy,
  service scoping, and operator-controlled port-forward paths. This decision
  does not add a Gateway or public exposure.
- The setting can be removed from recovery configs if a future Vault version
  changes the recovery endpoint model or if the owner chooses a different
  break-glass design.

## Alternatives Considered

1. Keep generate-root authenticated and rely on a captured token.

   Rejected. Snapshot restore replaces the token store, and token TTLs expire on
   wall-clock time. This can pass a same-day drill while failing the real delayed
   disaster-recovery scenario.

2. Keep token-less generate-root enabled on live Vault.

   Rejected. The unauthenticated family creates a bounded denial-of-service
   surface even though it cannot mint a root token without the recovery-key
   quorum. Because recovery automation can apply the directive to an isolated
   recovery workload every time, keeping the surface permanently enabled on live
   Vault is unnecessary.

3. Temporarily edit the live StatefulSet during break-glass.

   Rejected. In-place live edits create a cleanup dependency at the worst time.
   The replacement StatefulSet path makes the recovery surface explicit,
   isolated, and naturally disposable.

4. Enable unauthenticated `rekey` or `generate-operation-token` too.

   Rejected. Step 156 only needs standard `generate-root`. Widening the
   unauthenticated family list would add denial-of-service surface without
   solving the restore gate.

5. Use Vault recovery mode and raw storage manipulation.

   Rejected for this recovery path. Recovery mode is a last-resort storage
   surgery tool, not the ordinary restored-Vault access path. The desired
   operator workflow is recovery-key quorum to new root, then normal Vault APIs.

## Verification

Step 156 verified the directive mechanism before this live-base hardening:

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

This PR's placement verification is source-only and non-mutating:

1. The live base `vault.hcl` does not contain
   `enable_unauthenticated_access`.
2. The isolated `vault-drill` config retains
   `enable_unauthenticated_access = ["generate-root"]`.
3. `scripts/check-live-vault-config-invariants.sh` renders
   `clusters/talos-cluster/apps/vault/base` and fails if the live Vault
   ConfigMap data contains `enable_unauthenticated_access`.
4. Kyverno policy `protect-live-vault-config` denies CREATE/UPDATE of a live
   `vault-config` ConfigMap containing that directive.

No live Vault rollout, rolling restart, or generate-root execution is part of
this decision.

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
| NIST SP 800-53 Rev. 5 | SC-7 | Avoids a standing unauthenticated endpoint family on live Vault while allowing it only in isolated recovery configs. |
| NIST SP 800-53 Rev. 5 | CM-2 | Records and validates the live/recovery Vault configuration boundary in source-controlled artifacts. |
