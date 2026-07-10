# Offline validation — protect-dr-validate-boundary (runtime Kyverno ClusterPolicy)

Layer 2 of the DR restore-validator boundary. This suite validates
`clusters/talos-cluster/apps/kyverno/policies/protect-dr-validate-boundary.yaml` with the kyverno CLI
**v1.18.1** (the cluster's app version) WITHOUT a cluster, so it can be re-run before flipping the policy
from Audit to Enforce.

## Run
```
bash docs/kyverno-tests/protect-dr-validate-boundary/validate.sh
```
Requires `podman` (rootless). Every `fixtures/pass/*` must report `pass`, every `fixtures/fail/*` must
report `fail`. Exit 0 = all correct.

## What it proves
- **Attacks caught** (`fixtures/fail/`): un-suspended/rewritten/multi-container CronJob, bindings that reach the
  guarded SAs (Group) or bind a guarded Role, an `impersonate` ClusterRole, a `data-vault` `fromBackup` Volume, an
  arbitrary Deployment and a service-account-token Secret in dr-validate, a destructive Longhorn RecurringJob, a
  driver-selecting CCNP with egress, and a weakened approved-VAP.
- **No false-positives** (`fixtures/pass/`): the approved CronJob/VAP/binding, and Longhorn/Kyverno's own broad
  Helm-rendered RBAC (which Kyverno admission sees but the static CI guard never renders).

Full authoring-time result: 13 attacks FAIL, 53 legit/platform objects PASS, 0 false-positives.
