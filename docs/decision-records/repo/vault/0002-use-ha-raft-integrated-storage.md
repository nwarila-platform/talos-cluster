# ADR-0002: Use HA mode with integrated Raft storage

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-01                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Low                                     |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Deploy Vault as a 3-replica StatefulSet using the **integrated Raft** storage
backend, one pod per worker node, with a per-pod Longhorn PVC at `/vault/data`.

## Context and Problem Statement

The cluster has 3 control-plane + 3 worker nodes (cp1–3, w1–3). Workers are
schedulable; control planes carry a `NoSchedule` taint. Longhorn is the default
StorageClass (`longhorn`, 2-way replication). Vault needs durable, highly
available storage without standing up an external datastore.

## Decision Drivers

- HA without an external storage dependency.
- Survive the loss of a single worker node.
- Stable per-pod identity and persistent volumes (Raft requires both).

## Considered Options

1. **Integrated Raft, 3 replicas (StatefulSet).**
2. Single-node `file` storage (no HA).
3. External Consul/other storage backend.

## Decision Outcome

**Chosen: Option 1.** A `StatefulSet` with `replicas: 3`,
`serviceName: vault-internal` (headless, `publishNotReadyAddresses: true`),
`podManagementPolicy: Parallel`, hard `podAntiAffinity`
(`topologyKey: kubernetes.io/hostname`) so one Vault pod lands per worker, and
`volumeClaimTemplates` requesting `storageClassName: longhorn`. Raft peers
discover each other via `vault-{0,1,2}.vault-internal` and `retry_join`.

## Confirmation

`vault operator raft list-peers` shows 3 voters after init/unseal; killing one
pod preserves quorum and data; restart persistence is verified per the
verification plan. Storage-layering nuance (Longhorn 2× replication beneath
Raft's app-level replication) is tracked as a follow-up — a dedicated
`replicaCount: 1` StorageClass may be preferable; see verification plan.

## Consequences

### Positive
- HA and durability with no external store; tolerates one worker loss.

### Negative
- Raft quorum recovery after multi-node loss needs a documented runbook.
- Longhorn-under-Raft double replication is storage-inefficient unless tuned.

### Neutral
- Requires StatefulSet semantics (this is the first such workload on-cluster).

## Assumptions

- Longhorn honors `fsGroup: 65532` so UID 65532 can write the PVC (MUST verify
  live — some CSI drivers ignore `fsGroup`).

## Related ADRs

- [ADR-0003](0003-use-manual-shamir-unseal-initially.md) — unseal for Raft.
- [ADR-0007](0007-disable-mlock-accept-swap-risk.md) — mlock posture.
