# Talos Drift Read-Only App

This app runs an hourly in-cluster CronJob with a static Talos `os:reader`
talosconfig and a Kubernetes ServiceAccount that can only read the cluster
version/node/Flux health signals, get the exact
`dr-etcd-backup/etcd-snapshot` CronJob, and create namespace-local warning
Events.

The checker covers:

- `cluster/config.env` `TALOS_VERSION` against `talosctl version --short` for
  every declared node.
- `cluster/config.env` `KUBERNETES_VERSION` against the Kubernetes API server
  version and every declared node's kubelet version.
- Declared node hostnames and InternalIPs from `cluster/config.env` against
  Kubernetes Node status.
- Flux `Kustomization` and `HelmRelease` Ready status, suspension, stalled
  conditions, and drift-related status messages.
- The etcd snapshot CronJob's `status.lastSuccessfulTime`, failing closed with
  a distinct `EtcdSnapshotStale` Event when it is absent, malformed,
  future-dated, unreadable, or older than 26 hours.

The freshness check observes a successful Job exit, not the snapshot artifact.
It cannot prove that the PVC contains a decryptable snapshot. Warning Events
and a failed guard Job are detection signals only; no external paging sink is
configured.

It does not cover Talos machine config drift. Talos `machineconfig` contains
secrets and is admin-only, so a credential that can read it is not a strict
read-only credential. Machine-config drift detection is deferred to the future
apply path that will have an `os:admin` pod identity and protected environment.

`expected.env` is generated from `cluster/config.env` by:

```bash
python scripts/render-talos-drift-expected.py
```

The CI/local unit test checks that `expected.env` still matches
`cluster/config.env`.
