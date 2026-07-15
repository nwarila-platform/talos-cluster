# Vault config — Flux-reconciled (CP-4)

This directory is the source of truth for Vault configuration. As of CP-4 S4a
the managed set is **reconciled by the redhat-cop vault-config-operator**: git
policy/role CRs under [`managed/`](managed/) converge live Vault — no human
runs `vault write` for a managed object (zero-manual / everything-in-band).

> The operator's OWN scoped identity — the one credential it must never manage
> (the bootstrap paradox) — lives in [`bootstrap/`](bootstrap/README.md) and is
> seeded owner-watched, out-of-band, via
> `scripts/vault-config/seed-operator-bootstrap.sh` (CP-4 S2b, ADR-0028).

## Layout

| Path | State | Purpose |
|---|---|---|
| `managed/policy-*.yaml` | **reconciled** | redhatcop `Policy` CRs (type `acl`); `spec.policy` is the exact HCL the operator converges `sys/policies/acl/<name>` to |
| `managed/role-*.yaml` | **reconciled** | redhatcop `KubernetesAuthEngineRole` CRs converging `auth/kubernetes/role/<name>` |
| `auth/kubernetes/roles/*.json` | capture-only (S4b pending) | the 3 namespace-**selector** roles the operator CRD cannot express (below) |
| `bootstrap/` | out-of-band exception | the operator's own policy+role (ADR-0028); NEVER GitOps-applied |

Reconciliation wiring: the `vault-config-managed` Flux Kustomization
(`apps/kustomization-vault-config-managed.yaml`) applies `managed/` with
`prune: false` (adopt-before-prune; prune arms in S7 after the S6b
reference-safety guard), `dependsOn` vault + vault-config-operator, and
CEL health checks on `ReconcileSuccessful`.

## Guards (CI, fail-closed)

- `scripts/check-vault-policy-no-escalation.py` — deny-by-default allowlist on
  every managed policy grant, scanning **`Policy` CR `spec.policy` HCL** (and
  any legacy `policies/*.hcl`, none remain). The load-bearing OSS control: a
  git commit cannot introduce escalation HCL **through any manifest under
  `clusters/talos-cluster/`** (the guard's scan root). Known residual: a CR
  placed outside that root and pulled in via a cross-root kustomize
  `resources:` reference would evade the scan (Flux builds with
  LoadRestrictionsNone) — widening the scan to the whole repo is a booked
  hardening (S4a audit finding R1; pre-existing scope, not introduced here).
- `scripts/check-vault-config-operator-bootstrap-invariants.py` — the
  bootstrap-paradox invariants: the operator identity is never managed, the
  bootstrap grants enumerate exactly the managed set (CR-derived + captured),
  no delete on non-smoke paths, bootstrap never Flux-applied.

## S4b — the 3 selector roles (pending owner decision)

`tenant`, `vso-org-pull-hwg`, `vso-org-pull-nwp` bind tenant namespaces via
Vault's `bound_service_account_namespace_selector` (login-time, Vault-side
label match). `KubernetesAuthEngineRole` v0.8.49 cannot express that field —
its `targetNamespaceSelector` resolves the selector in Kubernetes at
*reconcile time* and writes a static `bound_service_account_namespaces` list
(the operator watches Namespaces, so the list converges on tenant
onboarding/offboarding, but login for a brand-new tenant namespace depends on
the operator being alive, and de-label revocation lags if it is down).
Adopting them as-is would silently REWRITE the live selector binding into a
static list. **Owner decision 2026-07-15: DEFER, booked as [TD-0008](../../../../../docs/tech-debt.md)** —
the fix to explore is an upstream `vault-config-operator` selector-passthrough
patch (no self-signed fork image); the selector→static-list rewrite is
rejected. They stay capture-only meanwhile; their captures are applied live
already, so treat the JSON files as DR material.

## Adoption verification

`scripts/vault-config/verify-adoption-parity.py` compares live Vault against
the managed CRs (policies byte-exact; roles field-by-field on the operator's
write projection). Run it before arming anything destructive and after the
first reconcile of any adoption change. Note: role reconciles are idempotent
RE-WRITES (the operator's equivalence check never matches for roles — typed
Go values vs JSON-decoded reads), so "adopted cleanly" is proven by read-back
parity, not by an absent write.

## DR / rebuild

On a cluster rebuild the managed set self-restores: seed the bootstrap
identity (`bootstrap/README.md`), let Flux install the operator, and the CRs
re-create every managed policy/role. The `{{identity.entity.aliases.…}}`
templates in tenant policies embed the **live k8s-auth mount accessor**
(`auth_kubernetes_fc0d86cb`) — on a rebuilt Vault the accessor differs and the
CR content must be re-pointed (booked follow-up: the operator's
`${auth/kubernetes/@accessor}` placeholder would make this portable, but it
needs a `sys/auth` read grant in the bootstrap policy and a guarded rollout —
do NOT flip it casually; an unresolved placeholder writes literally).

## The DR snapshot-backup leg

The `vault-snapshot-backup` policy/role pair is managed (adopted S4a). The
break-glass direct apply (`scripts/dr/apply-vault-snapshot-backup-live.sh`)
reads the SAME source of truth (`managed/policy-vault-snapshot-backup.yaml`)
so DR without a running operator stays possible without a second copy of the
policy content.
