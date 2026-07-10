# ADR-0024: Use Two-Layer Enforcement for the Restore-Validator Boundary

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-10                              |
| Authors        | Nick Warila (@NWarila), Codex implementation support |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | ADR-0019, ADR-0020, ADR-0023, restore-validator guard, guard self-test, Kyverno boundary policy, validate workflow |
| Informed       | future platform operators and reviewers |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Protect the ADR-0020 Vault restore-validator boundary with two complementary
layers: a fail-closed build-time CI guard and a runtime Kyverno admission
backstop. The CI guard blocks unsafe repository changes before merge. The
Kyverno policy sees the objects Kubernetes is actually asked to admit after Flux
and Helm have transformed them.

Neither layer is sufficient by itself. The required go-live order is: soak the
Kyverno policy in Audit, promote it to Enforce after false-positive review, and
only then un-suspend the ADR-0020 CronJob after the non-`vault` Longhorn
placement constraint and ADR-0023 signed first-party image have landed.

## Context and Problem Statement

ADR-0020 defined the Vault restore validator and its core security boundary:
net-new scratch identities, no live Vault credential reuse, no live Vault
resource mutation, scratch-only Longhorn restore, and a suspended restore-driver
CronJob. Its implementation notes record the native
`ValidatingAdmissionPolicy` that name-scopes Longhorn Volume creates by the
`dr-orchestrator` ServiceAccount, but they do not record the later two-layer
enforcement model now present in the repository.

That omission matters because the enforcement model is architecturally
significant. The repository now has a static boundary guard and regression
self-test wired into CI, plus a Kyverno runtime policy that ships in Audit mode.
Those controls define how future changes to the restore validator are reviewed,
tested, admitted, and eventually promoted to runnable DR automation.

Because ADR-0020 is already Accepted, adding this later enforcement strategy to
ADR-0020 would be a substantive post-acceptance rewrite. This ADR records the
separate enforcement decision while keeping ADR-0020 as the source for what the
validator is meant to do.

## Decision

Adopt a two-layer enforcement model for the ADR-0020 restore-validator boundary.

Layer 1 is the build-time guard in
`scripts/check-vault-restore-validator-boundaries.sh`. It is a closed-world
allowlist for the restore-validator footprint and related privilege paths. The
guard currently exposes 12 `assert_*` functions, with boundary checks covering:

1. the closed-world `dr-validate` and related Longhorn/VAP footprint;
2. Flux Kustomization transform boundaries for validator-rendering paths;
3. guarded ServiceAccount subject bindings;
4. guarded Role references;
5. workloads running as guarded ServiceAccounts;
6. unapproved destructive Longhorn RBAC;
7. unapproved Longhorn data-plane declarations;
8. identity impersonation;
9. driver-selecting `CiliumClusterwideNetworkPolicy` egress;
10. mutating admission that can rewrite driver, Longhorn, or VAP objects;
11. unexpected validating admission on the same surface; and
12. singleton object-presence (`assert_exactly_one`) for the approved boundary
    objects.

Beyond these 12 `assert_*` functions, the guard also runs inline exact-contract
checks for the CronJob, RBAC, the Longhorn VAP and its binding, the
`NetworkPolicy`, the `CiliumNetworkPolicy`, and the restore-driver script.

The guard renders the real Flux root at `clusters/talos-cluster` and renders
in-repository child Flux Kustomization paths that reference the repo source.
That render path is authoritative for CI. When `GUARD_OFFLINE=1` is set for
local or self-test use, the guard may fall back to a non-authoritative
whole-tree source walk after root or child renders are intentionally made
unavailable.

The guard self-test in
`scripts/check-vault-restore-validator-boundaries.selftest.py` forces the
offline fallback, runs a clean baseline, and then applies one change per case:
15 malicious negative cases that must make the guard fail, plus 2 benign
positive cases that must still pass. Most cases inject a probe manifest; two
mutate the CronJob directly. The negative cases exercise a representative
subset of the guard's finding classes — a regression sampler, not exhaustive
per-check coverage — so an edit that silently weakens a sampled class is caught
instead of merely proving that the clean repository still passes.

Layer 2 is the runtime Kyverno policy in
`clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml`.
It has 9 rules:

1. `cronjob-must-stay-suspended-and-pinned`;
2. `no-unapproved-binding-of-guarded-roles`;
3. `no-unapproved-subject-reaches-guarded-sa`;
4. `no-datavault-backup-restore`;
5. `no-unexpected-workload-or-secret-in-dr-validate`;
6. `no-impersonate-identity`;
7. `no-unapproved-longhorn-recurringjob`;
8. `approved-vap-integrity`; and
9. `no-driver-ccnp-egress`.

The Kyverno policy sees the real applied objects that admission receives after
Flux Kustomization transforms, Flux top-level patches, post-build substitution,
components, and Helm renders. Today it intentionally ships with
`validationFailureAction: Audit`, `webhookConfiguration.failurePolicy: Ignore`,
and `background: false`.

The two layers are complementary. The static CI guard gates pull requests before
merge and can fail closed in CI, but it cannot perfectly model all apply-time
Flux transforms or Helm-rendered platform objects. The Kyverno runtime policy
can evaluate admitted objects after those transforms, but it cannot stop a bad
pull request before merge and is intentionally non-blocking while in Audit.
Each layer covers most of the other's blind spot. The coverage is not a
complete partition: to stay false-positive safe against Helm-rendered platform
objects, the runtime policy deliberately defers three residual classes to the
git-declared CI guard — cluster-wide destructive Longhorn Role/ClusterRole
hygiene, broad mutating/validating webhook denial, and wildcard closed-world
`dr-validate` admission. Helm-rendered instances of those classes, which
`kubectl kustomize` never expands, therefore sit outside both layers' effective
reach. This residual is recorded in the policy header and accepted as a
deliberate trade.

The owner-gated go-live sequence is mandatory:

1. Soak `protect-dr-validate-boundary` in Audit on the live cluster and review
   PolicyReports for false positives on real Flux, Helm, operator, and manual
   apply traffic.
2. Promote the policy only after that review by changing
   `validationFailureAction` to `Enforce` and `failurePolicy` to `Fail`.
3. Only after runtime enforcement is active may the ADR-0020 Slice-2 CronJob be
   un-suspended, and only after the non-`vault` Longhorn placement constraint
   recorded as an ADR-0020 known limitation and the ADR-0023 signed
   first-party restore-driver image digest swap both land, and only after the
   driver has passed a supervised one-shot run as required by ADR-0020's
   implementation sequence.

## Consequences

### Positive

- Unsafe restore-validator boundary changes are caught before merge by a
  fail-closed CI guard.
- Runtime admission also checks the objects Kubernetes actually admits, covering
  Flux and Helm transform classes that a static render cannot fully model.
- The self-test proves covered attack classes still fail, not only that the
  clean repository still passes.
- Future reviewers have one place to understand why the static guard, self-test,
  Kyverno policy, and ADR-0020 CronJob state must agree.

### Negative

- Kyverno Audit mode is non-blocking until the owner promotes the policy to
  Enforce with a fail-closed webhook policy.
- Any future change to the restore-validator boundary must update the guard,
  self-test, Kyverno policy, and this ADR in lockstep or the layers will drift.
- Maintaining two enforcement layers costs more review effort than a single
  control, and false positives during Enforce promotion could block legitimate
  Flux reconciliation if the Audit soak is skipped.
- Three residual boundary classes (cluster-wide destructive Longhorn RBAC
  hygiene, broad mutating/validating webhook denial, and wildcard closed-world
  `dr-validate` admission) are enforced only by the git-declared CI guard;
  Helm-rendered instances of them are covered by neither layer, a deliberate
  false-positive trade recorded in the policy header.

### Neutral

- This ADR records the enforcement model already present in the repository; it
  does not change cluster behavior by itself.
- This ADR does not supersede ADR-0020. ADR-0020 remains the validator design;
  this ADR records how its boundary is enforced.
- This ADR does not un-suspend, schedule, or manually trigger the restore-driver
  CronJob.

## Alternatives Considered

1. Amend ADR-0020 with the two-layer enforcement model.

   Rejected. ADR-0020 is Accepted, and this later enforcement model is a
   substantive security decision. A new ADR preserves the historical validator
   decision and avoids rewriting an accepted record.

2. Rely only on the static CI guard.

   Rejected. The guard is the right pre-merge control, but it cannot perfectly
   see objects after apply-time Flux transforms, top-level patches, post-build
   substitution, components, or Helm renders.

3. Rely only on Kyverno admission.

   Rejected. Runtime admission sees the applied object, but it cannot provide a
   pre-merge review gate. While the policy is in Audit, it is also deliberately
   non-blocking.

4. Promote Kyverno directly to Enforce.

   Rejected for the current state. The policy header explicitly requires an
   Audit soak and PolicyReport review before Enforce plus Fail, because a buggy
   deny rule could block legitimate Flux reconciliation cluster-wide.

## Verification

This ADR is confirmed by the current repository state:

1. `scripts/check-vault-restore-validator-boundaries.sh` defines 12
   `assert_*` functions and performs additional inline exact-contract checks for
   the namespace, ServiceAccounts, RBAC, Longhorn VAP/B, NetworkPolicy,
   CiliumNetworkPolicy, CronJob, and restore-driver script.
2. `scripts/check-vault-restore-validator-boundaries.selftest.py` sets
   `GUARD_OFFLINE=1`, forces the offline fallback, verifies a clean baseline,
   verifies 15 negative cases fail, verifies 2 benign cases pass, and restores
   modified files and probe paths.
3. `clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml`
   defines 9 rules and currently sets `validationFailureAction: Audit`,
   `webhookConfiguration.failurePolicy: Ignore`, and `background: false`.
4. `.github/workflows/validate.yaml` runs both CI steps:
   `Guard: Vault restore-validator boundary` and
   `Guard self-test: restore-validator boundary regression`.
5. `docs/decision-records/README.md` indexes this ADR and reconciles the stale
   ADR-0020 index status to match ADR-0020's `Status: Accepted` metadata.

## Assumptions

1. The CI guard and self-test run in the `validate-kustomize` job, which already
   provisions the pinned `kubectl` and PyYAML the guard needs.
2. Kyverno v1.18.1 remains the cluster admission engine and the ClusterPolicy
   semantics this policy relies on are unchanged.
3. ADR-0020 remains the source of truth for what the restore validator may do;
   this ADR only governs how that boundary is enforced.

## Out of Scope

- Flipping Kyverno to Enforce, promoting the webhook to `failurePolicy: Fail`,
  un-suspending or scheduling the CronJob, and building or signing the ADR-0023
  image — all owner-gated (see the go-live sequence).
- Runtime coverage of Helm-rendered instances of the three deferred residual
  classes beyond the git-declared CI guard (see Consequences / Negative).
- Tenant, Keycloak, or application-level restore validation.

## Related

- [ADR-0019](0019-enable-tokenless-vault-generate-root.md) confines tokenless
  generate-root to scratch and recovery configs.
- [ADR-0020](0020-automate-vault-restore-validation.md) defines the restore
  validator and the suspended restore-driver CronJob this boundary protects.
- [ADR-0023](0023-nwarila-signed-image-for-dr-restore-driver.md) defines the
  signed first-party image digest-swap sequence required before un-suspending
  the restore-driver CronJob.
- [Restore-validator boundary guard](../../../scripts/check-vault-restore-validator-boundaries.sh)
  is the build-time CI guard.
- [Restore-validator boundary self-test](../../../scripts/check-vault-restore-validator-boundaries.selftest.py)
  is the guard regression test.
- [Kyverno runtime boundary policy](../../../clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml)
  is the admission backstop.
- [Validate workflow](../../../.github/workflows/validate.yaml) wires the guard
  and self-test into CI.

## Compliance Notes

| Framework             | Control | Relevance |
| --------------------- | ------- | --------- |
| NIST SP 800-53 Rev. 5 | CM-3    | Requires restore-validator boundary changes to pass controlled pre-merge validation and keep the ADR, CI guard, self-test, and runtime policy aligned. |
| NIST SP 800-53 Rev. 5 | CM-7    | Keeps the validator footprint closed-world and limits runnable workloads, admission surfaces, and Longhorn data-plane declarations to approved behavior. |
| NIST SP 800-53 Rev. 5 | AC-6    | Enforces least privilege for restore-validator ServiceAccounts, RBAC bindings, Longhorn access, and impersonation paths. |
| NIST SP 800-53 Rev. 5 | SI-7    | Detects unauthorized or integrity-breaking changes to the restore-validator boundary through CI assertions and runtime admission checks. |
| NIST SP 800-53 Rev. 5 | SA-11   | Maintains developer negative-path testing that proves covered attack classes fail rather than only validating the clean path. |
