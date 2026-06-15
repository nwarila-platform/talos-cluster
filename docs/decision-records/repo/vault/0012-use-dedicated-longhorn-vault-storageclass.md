# ADR-0012: Use a Dedicated Longhorn Vault StorageClass

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-10                              |
| Authors        | Nick Warila (@NWarila), Codex           |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | Longhorn 1.11.2 StorageClass parameter documentation |
| Informed       | Claude, future reviewers                |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## Context and Problem Statement

Vault runs three Raft peers, one pod per worker, but each pod also depends on a
Longhorn PVC for its local Raft data. During the 2026-06-10 worker
reprovisioning incident, the live Vault PVCs had only one healthy Longhorn
replica each and all of those replicas were on the worker being reprovisioned.
Wiping that worker therefore removed every Longhorn copy and took Vault down.

The cluster default `longhorn` StorageClass remains tuned for ordinary PVCs.
Vault is different: it is a bootstrap trust service, and a planned
one-worker-at-a-time reprovision must never leave a Vault volume with fewer than
two surviving healthy Longhorn replicas.

## Decision Drivers

1. Vault volumes must be created with three Longhorn replicas.
2. Replicas must use hard node anti-affinity so Longhorn does not co-locate
   multiple replicas for the same Vault volume on one node.
3. The change should avoid increasing storage cost for every future PVC by
   default.
4. The storage policy must be visible from the workload manifest.

## Considered Options

1. **Reference a dedicated `longhorn-vault` StorageClass from the StatefulSet.**
2. **Raise the cluster-wide default `longhorn` StorageClass to three replicas.**
3. **Keep the default StorageClass and rely on operator preflight checks only.**

## Decision Outcome

Chosen option: **Option 1, reference a dedicated `longhorn-vault` StorageClass.**

The Vault StatefulSet sets `storageClassName: longhorn-vault`. The
`talos-cluster` trust-root repository owns that StorageClass because it is a
cluster storage capability, while this repository owns the workload's explicit
request for it.

The class sets `numberOfReplicas: "3"` and disables Longhorn replica node soft
anti-affinity. Longhorn applies StorageClass parameters to newly provisioned
volumes only, so existing broken/faulted volumes still require a separate,
operator-gated recreate.

## Consequences

### Positive

- New Vault PVCs get three Longhorn replicas instead of inheriting the
  two-replica cluster default.
- Longhorn must place those replicas on distinct nodes when enough schedulable
  nodes exist.
- Future non-Vault workloads do not inherit the 3x storage cost unless they
  explicitly opt in.

### Negative

- The StatefulSet now depends on `talos-cluster` having reconciled the
  `longhorn-vault` StorageClass before Vault PVC recreation.
- Existing Vault PVCs are not mutated by this manifest change; they must be
  recreated in a separately gated live operation.

### Neutral

- This does not add off-host backups for Longhorn data. It only removes the
  one-worker reprovision single point of failure.

## Compliance Notes

This ADR supports availability and configuration-management evidence by making
Vault's storage redundancy explicit, source-controlled, and reviewable.

## Related ADRs

- ADR-0002: Use HA mode with integrated Raft storage.
- `talos-cluster` [ADR-0013](../0013-use-dedicated-vault-longhorn-storageclass.md): Use a dedicated Vault Longhorn StorageClass.
