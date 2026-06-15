# ADR-0007: Keep `disable_mlock=true` and accept the swap risk (no IPC_LOCK)

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-01                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | 2026-09-01                              |

## TL;DR

Run Vault with `disable_mlock = true` and **without** the `IPC_LOCK`
capability, so the pod stays compatible with Pod Security Standards
`restricted`. Mitigate the swap-exposure risk by relying on Talos having swap
disabled.

## Context and Problem Statement

Vault normally calls `mlock(2)` to keep secrets out of swap, which requires the
`IPC_LOCK` capability. The UBI9-micro image deliberately drops **all** capabilities,
and every target namespace enforces PSS `restricted`, which forbids adding
capabilities. So we must choose: add `IPC_LOCK` (violating `restricted`) or set
`disable_mlock = true` (Vault memory may be swappable).

## Decision Drivers

- PSS `restricted` enforcement on the namespace (no added capabilities).
- The image's "drop ALL capabilities" hardening invariant.
- The image's own `runtime-hardening.md` explicitly presents this exact choice.

## Considered Options

1. **`disable_mlock = true`, no `IPC_LOCK`, rely on swap being off.**
2. Add `capabilities.add: ["IPC_LOCK"]`, set `disable_mlock = false`, and grant a
   PSS exemption (label the namespace `baseline` / Kyverno PSA exception).

## Decision Outcome

**Chosen: Option 1.** Keep `disable_mlock = true`. Talos nodes run without swap
by default, which removes the practical swap-to-disk exposure that `mlock` guards
against. This keeps the Vault pod fully `restricted`-compliant and preserves the
image's drop-ALL-capabilities posture. This is also HashiCorp's recommended
posture for integrated (Raft) storage.

## Confirmation

The pod admits under PSS `restricted` (no capabilities added). Talos node
config is confirmed to have swap disabled before relying on this mitigation.

## Consequences

### Positive
- No PSS exemption needed; the security envelope stays uniform with other tenants.

### Negative
- If swap were ever enabled on a node, Vault secrets could be paged to disk.
  This must be re-evaluated if node swap policy changes (hence `Review-by`).

## Related ADRs

- [ADR-0002](0002-use-ha-raft-integrated-storage.md) — Raft + this posture.
