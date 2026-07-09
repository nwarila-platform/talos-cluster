# Vault Restore Validator

This directory implements ADR-0020 slice 2: a suspended, owner-run restore
driver for validating the newest eligible Vault Longhorn backup without
starting Vault or mounting restored data.

The driver restores only into the fixed scratch Longhorn volume
`dr-validate-vault-restore`, waits for Longhorn to finish the restore, compares
the restored volume size to the backup size, deletes the scratch volume, and
writes a non-secret PASS/FAIL result to ConfigMap
`dr-restore-driver-result`.

Safety invariants:

- the `dr-orchestrator` ServiceAccount has no standing token automount at the
  ServiceAccount object; only the suspended CronJob pod opts in;
- Longhorn `delete`, `patch`, and `update` on `volumes.longhorn.io` are
  `resourceNames`-scoped to `dr-validate-vault-restore` only;
- live `data-vault*` volumes are protected again by Kyverno policy
  `protect-live-vault-longhorn-volume`;
- the driver script refuses scratch names matching `data-vault*` and routes all
  cleanup through the fixed scratch name;
- namespace networking remains default-deny, with the driver allowed egress only
  to the Kubernetes API server through Cilium `toEntities: [kube-apiserver]`;
- the CronJob ships with `spec.suspend: true` and the inert Feb-31 schedule
  placeholder, so nothing runs automatically.

Manual supervised run:

```sh
kubectl create job --from=cronjob/dr-restore-driver dr-restore-<ts> -n dr-validate
```

This command is intentionally manual. Review the rendered manifests and current
Longhorn backup state before creating a Job.

Deferred ADR-0020 slices:

- scratch Vault;
- recovery-key quorum handling;
- tokenless generate-root;
- `enable_unauthenticated_access`;
- KV, PKI, or Vault API decrypt sampling;
- signed result artifacts;
- any automatic CronJob schedule.
