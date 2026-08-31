# dr1 — etcd DR backup repair implementation handoff

**Implemented:** 2026-08-31

**Baseline:** `origin/main@69b68fc`

**Branch:** `dr1-etcd-backup-repair`

## Delivered

- After validating the raw snapshot, the etcd producer takes a non-blocking
  exclusive lock on `/data` before deriving any artifact path or installing a
  cleanup trap. A contending run exits non-zero before invoking `date` or
  arming cleanup, so every partial and final remains untouched; kernel
  descriptor cleanup releases the lock when the pod dies.
- The producer removes partials independently, checks
  `ceil(raw_bytes / 3) * 4 + 1,009 + 134,217,728` bytes of free space,
  encrypts to an atomically created, run-unique temporary path, rejects
  implausibly small output, publishes without clobbering, and only then prunes
  canonical finalized artifacts to the newest 14. A terminal assertion proves
  the run's own artifact survived and the retained set remains bounded. Every
  deletion log records path and measured size immediately before `rm`.
- The PVC request is 32Gi. The current `.db.sops.json` contract and explicit
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
adding the 128 MiB safety margin. At the 15-artifact peak, the margin-adjusted
32 GiB ceiling is 2,281,701,376 bytes (2,176 MiB) per artifact. Compounding the
single observed 11.2% growth interval every 40 days reaches that ceiling in
approximately 339 days; this is a planning horizon, not a forecast. Three
Longhorn replicas allocate 96 GiB nominal for the 32 GiB request.

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
- Final-commit and live-cluster gate attestation remains owner-run. This ledger
  does not claim evidence from an operator-local path; the required offline
  command is `kubectl kustomize clusters/talos-cluster`, followed by each named
  repository guard and fixture against the final commit SHA.

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
- **dr2 / TD-0023:** reconcile the daily/14-artifact implementation and its
  26-hour guard with ADR-0014, which still requires every 6 hours, all runs for
  14 days, and originally paired that cadence with an 8-hour threshold.
  ADR-0014 now marks only the threshold as superseded pending dr2; its cadence
  remains unchanged.
- P2 observed Talos v1.13.5 versus pinned v1.13.7 and Kubernetes v1.36.2 versus
  pinned v1.36.3. That unrelated version drift was not changed in dr1.

## Post-Deployment Owner Gates

These gates cannot be completed without changing or reading live cluster state
and therefore remain owner-run after Flux applies the committed manifests:

1. Verify 32Gi at PVC request, PVC status, PV capacity, Longhorn `spec.size`,
   and mounted `df`, plus all three healthy replicas; shrinking is not a
   rollback option.
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
shrink the existing claim from 32Gi to 5Gi. If producer rollback is required,
leave the expanded claim in place while reverting the other resources.
