# dr1 — etcd DR backup repair implementation handoff

**Implemented:** 2026-08-31

**Baseline:** `origin/main@69b68fc`

**Branch:** `dr1-etcd-backup-repair`

## Delivered

- The etcd producer now takes a non-blocking exclusive lock on the mounted
  `/data` directory before any artifact mutation. A contending run exits
  non-zero without touching partials or finals, and kernel descriptor cleanup
  releases the lock when the pod dies.
- The producer removes partials independently, checks
  `ceil(raw_bytes / 3) * 4 + 1,009 + 134,217,728` bytes of free space,
  encrypts to a PID-scoped temporary path, rejects implausibly small output,
  publishes without clobbering, and only then prunes finalized artifacts to
  the newest 14. Every deletion log records path and measured size immediately
  before `rm`.
- The PVC request is 16Gi. The current `.db.sops.json` contract and explicit
  SOPS JSON output are unchanged.
- A Role in `dr-etcd-backup` grants only `get` on batch CronJob
  `etcd-snapshot`, bound to ServiceAccount `talos-drift/talos-drift`.
- The hourly drift checker fails closed when `lastSuccessfulTime` is absent,
  malformed, future-dated, unreadable, or older than 26 hours. It emits a
  separate `EtcdSnapshotStale` Event without putting Event delivery on the
  exit-code path.
- The retention renderer, hermetic producer fixtures, drift-check fixtures,
  sizing documentation, and 26-hour runbook threshold match the implementation.

For the measured 695,771,168-byte raw snapshot, the preflight projects a
927,695,901-byte SOPS artifact and requires 1,061,913,629 available bytes after
adding the 128 MiB safety margin.

## Artifact Path and Size Ledger

No live cluster object or DR PVC path was read, created, changed, or deleted
during P3 implementation. Consequently there are no live artifact paths or
sizes touched by this phase, and no live newest retained final can honestly be
recorded yet. The failure and ordering proofs used disposable filesystems only;
they did not mount or constrain the DR PVC.

The first post-deployment run must append the producer's exact records here:

```text
Deployment/manual-run timestamp:
Removed partial path + measured bytes:
Removed finalized path + measured bytes:
Newest retained finalized path + measured bytes:
Pre-prune free bytes:
Final free bytes:
```

## Local Evidence

- The producer fixture proves lock contention, lock release after process-group
  death, same-second no-clobber, capacity failure, SOPS failure, implausibly
  small output, independent partial cleanup, and write-then-prune behavior with
  0, 1, 14, and 15 pre-existing finals plus mixed legacy names.
- The drift fixture proves fresh, absent, exact 26-hour boundary, stale,
  malformed, API-read failure, unrelated-drift-only, combined stale and drift,
  future timestamp, distinct Event, and Event-POST-failure behavior.
- The full root Kustomize render, exact RBAC render assertions, DR value
  renderer and selftest, repository selftests, and focused Python syntax checks
  are recorded with their exact commands and output in
  `/home/hellbomb/dr1-exchange/DR1-P3-REPORT.md`.

## Accepted Residuals and Follow-Up

- `flock` is advisory and inode-scoped. A non-cooperating writer, out-of-band
  directory replacement, or administratively forced split-brain attachment can
  bypass it. The specified producer and prune paths do none of these.
- The freshness guard observes CronJob success status, not the artifact. It
  does not prove that a decryptable snapshot exists on the RWO PVC.
- A failed guard Job and expiring Kubernetes Event are detection, not paging.
  There is no external notification sink.
- The restore runbook requires a snapshot manifest that this pipeline still
  does not produce. Artifact validation and a sacrificial restore drill remain
  separate gates.
- **dr2:** reconcile the daily/14-artifact implementation with ADR-0014, which
  still requires every 6 hours, all runs for 14 days. ADR-0014 was not edited.
- P2 observed Talos v1.13.5 versus pinned v1.13.7 and Kubernetes v1.36.2 versus
  pinned v1.36.3. That unrelated version drift was not changed in dr1.

## Post-Deployment Owner Gates

These gates cannot be completed without changing or reading live cluster state
and therefore remain owner-run after Flux applies the committed manifests:

1. Verify the resize at PVC request, PVC status, PV capacity, Longhorn
   `spec.size`, mounted `df`, and all three healthy replicas; shrinking is not
   a rollback option.
2. Record the deployment/manual-run timestamp, run the CronJob, and prove
   `lastSuccessfulTime` advances past that timestamp.
3. Append every producer-reported path and size plus the newest retained final
   to the ledger above. Do not create surplus live files or run a destructive
   test prune.
4. Decrypt the newest artifact and validate it with a pinned compatible
   `etcdutl snapshot status`; do not call that a restore drill.
5. Prove a subsequent `etcd-daily-backup` for this volume reaches `Completed`
   after the new artifact is committed.

## Rollback

Revert the implementation commit and reconcile Flux to restore the producer,
RBAC, guard, and documentation. The PVC expansion is one-way: do not attempt to
shrink the existing claim from 16Gi to 5Gi. If producer rollback is required,
leave the expanded claim in place while reverting the other resources.
