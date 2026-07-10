# DR Validate Boundary Enforce Hardening

This runbook promotes the existing DR restore-validator Kyverno boundary from
Audit/Ignore to Enforce/Fail after a clean soak.

It is Path A from
[ADR-0024](../decision-records/repo/0024-two-layer-enforcement-of-restore-validator-boundary.md):
harden the current inert boundary. It is not a go-live runbook for scheduled
restore validation.

## Scope

This runbook does one thing: make
`ClusterPolicy/protect-dr-validate-boundary` fail closed for the current inert
restore-validator boundary.

In scope:

1. Review the Audit soak evidence for
   `ClusterPolicy/protect-dr-validate-boundary`.
2. Change only these two policy fields through a GitOps PR:
   `spec.validationFailureAction` and
   `spec.webhookConfiguration.failurePolicy`.
3. Verify the live policy is Enforce/Fail, a known-bad dry-run object is
   denied, and legitimate Flux reconciliation still succeeds.

Out of scope:

- un-suspending `CronJob/dr-restore-driver`;
- changing its inert schedule `"0 6 31 2 *"`;
- creating a manual restore-validation `Job`;
- changing the static guard or Kyverno rules to permit live scheduled
  operation.

## Hard Stops

Stop before opening the promotion PR if any item is false:

- The Audit soak has run on the live cluster long enough to include normal Flux,
  Helm, operator, and owner apply traffic.
- The owner has reviewed the PolicyReport evidence and confirmed no legitimate
  apply was flagged by `protect-dr-validate-boundary`.
- `ClusterPolicy/protect-dr-validate-boundary` is still the expected policy in
  `clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml`.
- `CronJob/dr-restore-driver` is still suspended with schedule
  `"0 6 31 2 *"` in
  `clusters/talos-cluster/apps/vault-restore-validator/cronjob.yaml`.
- The static guard still pins the same inert contract in
  `scripts/check-vault-restore-validator-boundaries.sh`.
- The owner is present for the promotion and rollback window.
- Everyone involved understands this is terminal-for-inert: once Enforced,
  un-suspending the CronJob or creating an ad hoc supervised Job is denied by
  the current controls.
- Everyone understands the blast radius: under `failurePolicy: Fail`, a single
  false-positive denial — or a Kyverno webhook outage — blocks admission of the
  matched kinds cluster-wide, including Flux's own reconciliation apply (rule
  `no-impersonate-identity` alone matches every `Role`/`ClusterRole`). The Audit
  soak and PolicyReport review are therefore mandatory, not advisory.

Rollback is only a GitOps rollback: revert the promotion PR, then reconcile
Flux. Do not use `kubectl edit`, `kubectl patch`, or `kubectl apply` to mutate
the live policy during promotion or rollback.

## Required Inputs

- Repository branch for the promotion PR.
- Owner-approved Audit soak record.
- `kubectl` access to the production cluster.
- `flux` CLI access to `flux-system`.
- `jq` for PolicyReport filtering.
- The policy path:
  `clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml`.
- The guard path:
  `scripts/check-vault-restore-validator-boundaries.sh`.
- The CronJob path:
  `clusters/talos-cluster/apps/vault-restore-validator/cronjob.yaml`.

## Step 1: Audit-Soak Verification

Confirm the policy is still in Audit/Ignore before relying on report evidence:

```bash
kubectl get clusterpolicy protect-dr-validate-boundary \
  -o jsonpath='{.spec.validationFailureAction}{"\n"}{.spec.webhookConfiguration.failurePolicy}{"\n"}'
```

Expected output before promotion:

```text
Audit
Ignore
```

List the report objects that Kyverno has produced:

```bash
kubectl get clusterpolicyreport,policyreport -A
```

Extract every recorded result for this policy:

```bash
kubectl get clusterpolicyreport,policyreport -A -o json |
jq -r '
  .items[]
  | .metadata as $report
  | (.results // [])[]
  | select(.policy == "protect-dr-validate-boundary")
  | [
      ($report.namespace // "-"),
      $report.name,
      .rule,
      .result,
      ((.resources // [])
        | map((.namespace // "-") + "/" + .kind + "/" + .name)
        | join(",")),
      (.message // "-")
    ]
  | @tsv
'
```

Review every `fail` result. A clean soak means there are no failures for
legitimate Flux, Helm, operator, or owner apply traffic. Unknown failures are
not clean evidence; identify the object and either fix the false positive or
stop before Enforce.

Also confirm the source-controlled inert contract still matches the current
boundary:

```bash
grep -nE 'validationFailureAction|failurePolicy|cronjob-must-stay-suspended-and-pinned|no-unexpected-workload-or-secret-in-dr-validate' \
  clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml

grep -nE 'spec.suspend: true|0 6 31 2|Job/.+forbidden|must ship spec.suspend|inert Feb-31' \
  scripts/check-vault-restore-validator-boundaries.sh

grep -nE 'suspend: true|schedule: "0 6 31 2 \*"' \
  clusters/talos-cluster/apps/vault-restore-validator/cronjob.yaml
```

## Step 2: Promote To Enforce

Make one GitOps PR that edits only the two policy values in
`clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml`:

```diff
-  validationFailureAction: Audit
+  validationFailureAction: Enforce
@@
-    failurePolicy: Ignore
+    failurePolicy: Fail
```

Do not change `CronJob/dr-restore-driver`, the inert schedule, the static guard,
or any Kyverno rule in this Path A PR.

Before merge, verify the rendered repository state:

```bash
kubectl kustomize clusters/talos-cluster/apps/kyverno/policies >/tmp/kyverno-policies.yaml
kubectl kustomize clusters/talos-cluster >/tmp/talos-cluster.yaml
bash scripts/check-vault-restore-validator-boundaries.sh
```

After the PR merges, reconcile through Flux:

```bash
flux reconcile source git flux-system -n flux-system
flux reconcile kustomization kyverno-policies -n flux-system --with-source
```

Verify the live policy shows Enforce/Fail:

```bash
kubectl get clusterpolicy protect-dr-validate-boundary \
  -o jsonpath='{.spec.validationFailureAction}{"\n"}{.spec.webhookConfiguration.failurePolicy}{"\n"}'
```

Expected output:

```text
Enforce
Fail
```

Verify rule `cronjob-must-stay-suspended-and-pinned` denies a bad dry-run
CronJob update:

```bash
kubectl -n dr-validate patch cronjob dr-restore-driver \
  --type=merge \
  --dry-run=server \
  -p '{"spec":{"suspend":false}}'
```

Expected result: admission denies the request. The command must not persist a
CronJob update because it is server-side dry-run.

Verify rule `no-unexpected-workload-or-secret-in-dr-validate` denies a bad
dry-run Job:

```bash
kubectl -n dr-validate create job dr-boundary-deny-probe \
  --image=busybox:1.36 \
  --dry-run=server \
  -- /bin/true
```

Expected result: admission denies the request. The command must not create a
Job because it is server-side dry-run.

Verify legitimate Flux reconciliation still succeeds:

```bash
flux reconcile kustomization flux-system -n flux-system --with-source
flux get kustomizations -n flux-system kyverno-policies flux-system
```

## Rollback

Rollback is a GitOps PR revert, not a live edit.

1. Revert the promotion PR so the policy returns to:

   ```yaml
   validationFailureAction: Audit
   webhookConfiguration:
     failurePolicy: Ignore
   ```

2. Merge the revert PR.
3. Reconcile Flux:

   ```bash
   flux reconcile source git flux-system -n flux-system
   flux reconcile kustomization kyverno-policies -n flux-system --with-source
   ```

4. Verify the live policy is back to Audit/Ignore:

   ```bash
   kubectl get clusterpolicy protect-dr-validate-boundary \
     -o jsonpath='{.spec.validationFailureAction}{"\n"}{.spec.webhookConfiguration.failurePolicy}{"\n"}'
   ```

## Un-Suspend / Live Operation Is Out Of Scope And Blocked

Do not un-suspend `CronJob/dr-restore-driver` in this runbook.

The current boundary's three controls (spanning both enforcement layers)
intentionally block live operation:

- Kyverno rule `cronjob-must-stay-suspended-and-pinned` denies the CronJob unless
  it keeps `spec.suspend: true` and schedule `"0 6 31 2 *"`.
- `scripts/check-vault-restore-validator-boundaries.sh` errors unless the
  CronJob ships with `spec.suspend: true`, the same inert Feb-31 schedule
  placeholder, and no in-repository `Job`.
- Kyverno rule `no-unexpected-workload-or-secret-in-dr-validate` denies `Job`,
  `Pod`, other runnable workload kinds, and `Secret` objects in `dr-validate`
  unless their owner reference names `dr-restore-driver` or starts with
  `dr-restore-driver-`; a manual
  `kubectl create job --from=cronjob/dr-restore-driver` Job does not satisfy
  that owner-reference gate.

Live scheduled operation must follow ADR-0024 Path B: a reviewed slice that
co-evolves rule `cronjob-must-stay-suspended-and-pinned`, the static guard, and
rule `no-unexpected-workload-or-secret-in-dr-validate` to define the approved
live schedule and behavior, after the non-`vault` Longhorn placement constraint
and ADR-0023 signed restore-driver image are ready.

## Pass Criteria

This runbook passes only if all criteria are true:

- The owner-approved Audit soak has no unexplained legitimate-apply failures for
  `protect-dr-validate-boundary`.
- The promotion PR changes only
  `spec.validationFailureAction: Enforce` and
  `spec.webhookConfiguration.failurePolicy: Fail`.
- `kubectl kustomize clusters/talos-cluster/apps/kyverno/policies` succeeds.
- `kubectl kustomize clusters/talos-cluster` succeeds.
- `bash scripts/check-vault-restore-validator-boundaries.sh` succeeds.
- The live policy reports Enforce/Fail after Flux reconciliation.
- The bad dry-run CronJob update is denied.
- The bad dry-run Job create is denied.
- `Kustomization/kyverno-policies` and root `Kustomization/flux-system`
  reconcile successfully after promotion.

## Record Template

```text
Date/time UTC:
Operator:
Reviewer/owner:
Promotion PR:
Promotion commit:
Policy path:
Guard path:
CronJob path:
Audit soak window:
PolicyReport command:
PolicyReport evidence location:
Pre-merge validation commands:
Flux reconcile commands:
Live policy result:
Bad CronJob dry-run result:
Bad Job dry-run result:
Flux health result:
Rollback PR, if used:
Residual risk / follow-up:
```
