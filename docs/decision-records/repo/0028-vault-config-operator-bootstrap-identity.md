# ADR-0028: vault-config-operator Bootstrap Identity (the owned out-of-band exception)

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-15                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

The vault-config-operator (CP-4) authenticates each reconcile via a Vault
Kubernetes-auth role backed by a scoped ACL policy. That identity — the
operator's own `auth/kubernetes/role/vault-config-operator` + `sys/policies/acl/vault-config-operator`
— is the **one credential the operator is NOT allowed to manage.** It is
excluded from the managed set and applied **once, owner-watched, out-of-band**
(`scripts/vault-config/seed-operator-bootstrap.sh`), never by GitOps and never by
the operator itself. In OSS Vault this identity is root-equivalent-in-practice
and cannot be bounded by ACL; it is bounded by defense-in-depth and its residual
is recorded here honestly.

## Context and Problem Statement

CP-4 makes `apps/vault/vault-config/` genuinely Flux-reconciled via the
redhat-cop vault-config-operator, retiring the banned hand-typed `vault write`.
The operator holds no standing Vault credential: each CR carries an
`authentication: {path, role, serviceAccount}` block and performs a per-reconcile
Kubernetes-auth login for a short-lived token. That login needs a pre-existing
Vault role + backing policy for the operator's service account — a
chicken-and-egg bootstrap.

Two hard truths from the CP-4 design pass shape this decision:

1. **The reconciler is root-equivalent, and OSS Vault cannot prevent it.** A
   credential that can author ACL **policy content** (`sys/policies/acl/:name`,
   which is not sudo-gated) **and** bind policies to auth roles
   (`auth/kubernetes/role/:name`) can author a `path "*" { capabilities =
   ["sudo", ...] }` policy under an allowed name, bind it to a role it controls,
   log in fresh, and obtain a root-equivalent token. Name enumeration bounds
   *where* it writes, never *what privilege* the written policy grants. Only
   Enterprise Sentinel/Control-Groups/Namespaces bound this at write time; we run
   OSS/Community, where none exist.

2. **The bootstrap paradox.** The operator manages auth roles and policies —
   potentially including its own. If it could rewrite its own policy it would
   self-escalate trivially; if it could prune its own role it would self-lock-out.

## Decision

- The operator's own role + policy are **excluded from the managed set** and are
  the **single owned, out-of-band bootstrap exception** — applied once by the
  owner-watched seed script with a short-TTL admin token, never by GitOps, never
  by the operator, never pruned. This is analogous to the declared USB-at-rack
  and air-gapped root-ceremony exceptions, and to "rotate the authorizer last."
- The bootstrap policy HCL lives in
  `apps/vault/vault-config/bootstrap/` — **outside** the S0 escalation guard's
  managed-policy scan scope (`apps/vault/vault-config/policies/`), because it
  legitimately grants the management-plane paths (`sys/policies/acl/*`,
  `auth/kubernetes/role/*`, `sys/mounts/pki-int-tcn`) that the S0 guard is built
  to reject in a *managed* policy. It is deliberately **not** a redhatcop Policy
  CR (a CR would make the operator manage its own policy → self-escalate).
- **Scope discipline (design control 3):** exact-path enumeration per managed
  object for auditability. Real managed objects get `[create, read, update]`
  only — **no `delete`** until prune is deliberately armed (CP-4 S7, gated on the
  S6b reference-safety guard). Only throwaway `*-smoke` paths carry `delete`, so
  the S3 smoke test can prove the full create/adopt/delete lifecycle without ever
  being able to delete a live object.
- The identity binds an **unforgeable SA name** — the dedicated, pod-less
  `vault-config-operator-vault` SA in ns `vault-config-operator` — with
  `token_no_default_policy: true` and a short 15m/30m TTL.
- A CI guard (`scripts/check-vault-config-operator-bootstrap-invariants.py`)
  enforces the separation: the bootstrap files are never a redhatcop Policy CR,
  never placed in the managed policy dir, and never referenced by a Flux
  kustomization (so GitOps can never apply them and the operator can never manage
  them).

## Consequences

- **Positive:** the operator gains no more Vault privilege than it needs; the
  git path to escalation is closed (S0 guard on managed content + this identity
  out of the managed set); the seed is idempotent, byte-verified, and revokes its
  admin token; PKI needs no sudo (`sys/mounts` is not sudo-gated), so the whole
  remit runs sudo-free.
- **Residual (owned, honest):** an attacker who compromises the running operator
  pod **within its short token window** obtains Vault root. This is real,
  bounded, and unavoidable in OSS Vault. It is the same trust class already
  accepted for VSO, source-rotator, and the DR-backup pods — not a new exposure —
  and it is a concrete data point for a future Enterprise-vs-OSS decision.
- **Operational:** adding a genuinely new managed Vault object (rare — the tenant
  model is universal, not per-tenant) is a reviewed edit to the bootstrap policy
  plus an owner-watched re-seed. Arming prune (S7) adds `delete` via the same
  reviewed re-seed.

## Alternatives Considered

- **Bind the operator's controller-manager SA directly** (no dedicated SA):
  rejected — couples the pod identity to the Vault-auth identity and muddies the
  audit trail. A dedicated pod-less SA is cleaner separation for the same cost.
- **Split authoring from binding across two credentials** (defeat the
  root-equivalence structurally): deferred — the Aug-11 cert clock argues against
  gold-plating v1, and the first slice's authoring is pinned to git-reviewed named
  objects behind the S0 guard. Revisit if the threat model warrants.
- **Enterprise Vault (Sentinel):** the only thing that actually bounds this at
  write time, but not proportionate at this scale; recorded as a future data
  point.

## References

- CP-4 design: `_handoff/CP4-VAULT-CONFIG-RECONCILER-DESIGN.md` (decisions #2, #4;
  §3 the root-equivalence crux).
- S0 escalation guard: `scripts/check-vault-policy-no-escalation.py` (ADR context:
  deny-by-default managed-policy allowlist).
- ADR-0015 (tenant Vault capability), ADR-0019 (generate-root gating).
