# vault-config-operator bootstrap identity — the owned, out-of-band exception

This directory holds the **one credential the vault-config-operator is NOT
allowed to manage: its own.** Per the CP-4 design (decision #4, the "bootstrap
paradox") and ADR-0028, the operator's own Vault k8s-auth role + scoped ACL
policy are excluded from the managed set and applied **once, owner-watched,
out-of-band** — never by GitOps, never by the operator itself.

## Why here (and why NOT under `../policies/`)

`vault-config-operator.policy.hcl` legitimately grants **management-plane** paths
(`sys/policies/acl/*`, `auth/kubernetes/role/*`, `sys/mounts/pki-int-tcn`) so the
operator can manage the platform's Vault config. Those are exactly the paths the
**S0 escalation guard** (`scripts/check-vault-policy-no-escalation.py`) is
designed to **reject in a *managed* policy**. So this file lives OUTSIDE the
guard's scan scope (`apps/vault/vault-config/policies/`) and is **not** a
`redhatcop.redhat.io/v1alpha1` Policy CR — a CR would make the operator manage
its own policy → self-escalate.

The CI guard `scripts/check-vault-config-operator-bootstrap-invariants.py`
enforces that this separation holds (bootstrap files are never CRs, never in the
managed policy dir, never referenced by a Flux kustomization).

## Files

| Path | Purpose |
|---|---|
| `vault-config-operator.policy.hcl` | The operator's scoped ACL policy. Exact-path enumeration of the managed set (7 policies + 6 roles + the `pki-int-tcn` mount), `[create, read, update]` only (no delete until prune is armed in S7); `*-smoke` throwaway paths carry delete for the S3 lifecycle proof. |
| `vault-config-operator.role.json` | The operator's `auth/kubernetes/role/vault-config-operator` — binds the unforgeable SA name `vault-config-operator-vault` in ns `vault-config-operator`, `token_no_default_policy`, 15m/30m TTL. |

The dedicated Vault-auth SA `vault-config-operator-vault` is GitOps-applied via
`apps/vault-config-operator/release/serviceaccount-vault.yaml` (a benign
identity-only SA; it never runs a pod and does not auto-mount a token).

## Apply (owner-watched, CP-4 S2b)

```sh
# With a SHORT-TTL minted admin token (VAULT_TOKEN or ../admin-token.json):
REVOKE_TOKEN_AFTER=true scripts/vault-config/seed-operator-bootstrap.sh
```

The script applies the policy + role, reads them back, asserts the live policy
equals this HCL byte-for-byte, and (opt) self-revokes the admin token. It never
prints the token or the policy/role bodies.

## The residual (recorded honestly — ADR-0028)

In OSS Vault a credential that can author policy content **and** bind policies to
roles is root-equivalent, and no ACL can bound it (only Enterprise Sentinel can).
This identity is that credential. It is bounded by defense-in-depth — short-TTL
per-reconcile k8s-auth (no standing token), a restricted-PSA egress-to-Vault-only
pod, and the S0 guard on the CONTENT of every *managed* policy — leaving the
owned residual: "an attacker who compromises the running operator pod during its
short token window gets Vault root." Real, bounded, and a data point for the
eventual Enterprise-vs-OSS decision.

## vault-admin — the break-glass admin capture (owner decision 2026-07-15)

[`vault-admin.policy.hcl`](vault-admin.policy.hcl) is the grant-identical,
LF-normalized capture of the live `sys/policies/acl/vault-admin` policy (the
raw live body carries one trailing CRLF; every grant line is byte-identical) —
the identity attached to the durable admin token minted by the 2026-07-14
generate-root break-glass (`_handoff/VAULT-LIVE-ADMIN-RECOVERY-RUNBOOK.md`).
Same paradox class as the operator identity: **never operator-managed, never
GitOps-applied** — a repo compromise must not be able to rewrite or neuter the
recovery identity. The invariants guard enforces this (protected-identity set,
case-folded and List-envelope-aware: no redhatcop CR may carry the name, the
operator bootstrap policy may never cover its path, and no managed
`vault-admin.hcl` may exist). Re-applied only by the owner during a
break-glass ceremony; if the live policy is ever changed deliberately,
re-capture it here in the same PR that records why.
