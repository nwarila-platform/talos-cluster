# ADR-0013: Use a Dedicated Vault Longhorn StorageClass

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-10                              |
| Authors        | Nick Warila (@NWarila), Codex           |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | Longhorn 1.11.2 StorageClass and scheduling documentation |
| Informed       | Claude, future reviewers                |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## Context and Problem Statement

Vault went down during the w1 SecureBoot+TPM reprovision because the live
Longhorn volumes backing `data-vault-0`, `data-vault-1`, and `data-vault-2`
had drifted to one healthy replica each, and all three healthy replicas were on
w1. The `longhorn` default StorageClass was configured for two replicas, which
is too little margin for planned one-worker-at-a-time reprovisioning of a
bootstrap trust service.

Vault was empty and backed up, so no data was lost. The incident still exposed a
repo-level storage policy gap: new Vault PVCs must be created with enough
Longhorn redundancy that losing one worker leaves at least two healthy copies.

## Decision Drivers

1. New Vault PVCs must request three Longhorn replicas.
2. Longhorn must not co-locate multiple replicas for one Vault volume on the
   same node when enough schedulable nodes exist.
3. Ordinary PVCs should not inherit 3x storage cost unless they opt in.
4. The platform trust root should own cluster-scoped storage policy, while the
   workload repo should explicitly request that policy.
5. Existing broken volumes must not be mutated by this repo-only step; the live
   recreate remains a separate owner-gated operation.

## Considered Options

1. **Add a dedicated `longhorn-vault` StorageClass and point Vault at it.**
2. **Raise the default `longhorn` StorageClass and Longhorn default replica
   count to three.**
3. **Keep StorageClass defaults unchanged and rely only on operator preflight
   checks.**

## Decision Outcome

Chosen option: **Option 1, add a dedicated `longhorn-vault` StorageClass.**

`clusters/talos-cluster/apps/longhorn-vault-storage/storageclass.yaml` defines a
Flux-owned, non-default StorageClass with:

- `numberOfReplicas: "3"`
- `dataLocality: disabled`
- `replicaSoftAntiAffinity: disabled`
- `replicaDiskSoftAntiAffinity: disabled`

`deploy-vault` now requests `storageClassName: longhorn-vault` in the Vault
StatefulSet volume claim template, and this repository pins the deploy-vault
GitRepository to that reviewed commit.

Longhorn's StorageClass parameters apply to newly provisioned volumes only.
This PR does not touch live PVCs, replicas, or Longhorn settings. The existing
faulted Vault volumes must be recreated in a separately gated live step.

## Pros and Cons of the Options

### Option 1: Dedicated `longhorn-vault` StorageClass (chosen)

- **Good, because** Vault gets three replicas without changing storage cost for
  every present and future default-class PVC.
- **Good, because** replica node soft anti-affinity is explicit on the class
  that needs the guarantee.
- **Good, because** the workload manifest makes the special storage policy
  visible at the claim site.
- **Bad, because** it introduces a cluster-scoped capability that must reconcile
  before Vault PVC recreation.

### Option 2: Raise the cluster-wide default to three replicas

- **Good, because** no workload manifest changes would be required.
- **Bad, because** every default Longhorn PVC would consume 3x storage, even
  when it is not a bootstrap dependency.
- **Bad, because** it hides the Vault-specific availability requirement inside
  a broad default.

### Option 3: Operator preflight only

- **Good, because** it avoids manifest churn.
- **Bad, because** it would not fix future PVC provisioning. The preflight is a
  necessary guard, not the desired state.

## Consequences

### Positive

- New Vault volumes should provision with three replicas on distinct schedulable
  Longhorn nodes.
- Losing or reprovisioning one worker should leave two surviving replicas if
  the preflight confirms the actual live placement before the node is drained or
  powered down.
- The default `longhorn` class remains at two replicas for ordinary workloads.

### Negative

- The guarantee is limited to new volumes. Existing PVCs keep their old
  StorageClass parameters until recreated.
- Worker-only placement cannot be proven from repo state alone unless Longhorn
  worker node tags are also declared and verified. The runbook therefore gates
  each reprovision on observed live replica placement: for Vault, at least two
  healthy replicas must already exist on the other workers.

### Neutral

- This does not add off-host Longhorn backups. It removes the one-worker
  single point of failure exposed by the w1 incident, but a broader backup
  target and restore drill remain separate work.

## Confirmation

1. `kubectl kustomize clusters/talos-cluster` renders a StorageClass named
   `longhorn-vault` with `numberOfReplicas: "3"` and
   `replicaSoftAntiAffinity: disabled`.
2. The rendered deploy-vault GitRepository pins to a commit whose Vault
   StatefulSet requests `storageClassName: longhorn-vault`.
3. `docs/runbooks/reprovision-secureboot-node.md` requires a Longhorn
   replica-health preflight before any worker is drained or powered down.

## Related ADRs

- ADR-0007: Capture the Longhorn Helm Release as a Managed Addon.
- ADR-0011: Auto-Discover Deploy Repositories by Convention.
- ADR-0012: Vault KMS Auto-Unseal - AWS Credential Delivery, Egress, and Key Model.
- deploy-vault ADR-0012: Use a Dedicated Longhorn Vault StorageClass.
