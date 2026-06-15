# ADR-0003: Use manual Shamir unseal initially; defer auto-unseal

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Superseded by [ADR-0008](0008-adopt-kms-auto-unseal.md) |
| Date           | 2026-06-01                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | 2026-09-01                              |

> **Superseded (2026-06-02) by [ADR-0008](0008-adopt-kms-auto-unseal.md).** The
> deferred auto-unseal risk this ADR named as its headline negative has been
> resolved: the cluster now uses AWS KMS auto-unseal. This record is retained for
> history. Recovery/escrow handling moved to
> [ADR-0009](0009-recovery-escrow-and-bootstrap-ceremony.md).

## TL;DR

For the first deployment, unseal Vault manually using **Shamir key shares**.
**Auto-unseal** (Transit or cloud KMS) is explicitly **deferred** and tracked as
a known operational risk.

## Context and Problem Statement

Vault starts sealed and must be unsealed after every pod restart/reschedule.
There is no existing KMS/HSM/Transit decision in the portfolio, and this is a
self-hosted, headless GitOps cluster. We need a defined, safe unseal model for
day one without inventing external dependencies.

## Decision Drivers

- No existing KMS/HSM/Transit Vault to depend on.
- Init/unseal/root-token material must never enter git ([ADR-0006], deny-all).
- A first deploy must be operable and recoverable.

## Considered Options

1. **Manual Shamir unseal** (key shares held by the operator, offline).
2. Auto-unseal via cloud KMS (requires a cloud KMS + credentials).
3. Auto-unseal via a Transit Vault (requires a second, already-unsealed Vault).

## Decision Outcome

**Chosen: Option 1 for now.** `vault operator init` produces N Shamir shares
with threshold T (default 5/3). Shares and the initial root token are captured
**out-of-band** during a documented ceremony
([`deploy-vault` bootstrap-and-unseal procedure](https://github.com/nwarila-platform/deploy-vault/blob/main/docs/how-to/bootstrap-and-unseal.md)),
never committed. After init, the operator immediately creates a least-privilege
admin and **revokes the initial root token**. Each pod restart requires manual
re-unseal (threshold shares) until auto-unseal is adopted.

## Confirmation

`vault status` shows `Sealed: false` and `HA Mode: active/standby` after the
ceremony; a sealed-after-restart recovery runbook is exercised.

## Consequences

### Positive
- No external KMS dependency for day one; full operator control of key material.

### Negative
- **Operational burden + risk:** every restart needs manual unseal; a full
  outage requires a human with the shares. This is the headline deferred risk.

### Neutral
- Migrating to auto-unseal later is supported (`vault operator unseal-migration`).

## Related ADRs

- [ADR-0006](0006-pin-and-verify-the-image.md) — no secret material in git.
