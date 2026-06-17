# ADR-0002: Use Short Talos Hostnames (`cp1`–`w3`) Rather Than Asset-Style Names

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-25                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Talos hostnames, Kubernetes node names, and per-node patch filenames in this repository are the short forms `cp1`, `cp2`, `cp3`, `w1`, `w2`, `w3`. The asset-style names `TDNHQ-TLOMGT0N` / `TDNHQ-TLOWRK0N` are retained only in the `systems` inventory file as a cross-reference between the cluster and the site-level physical-asset inventory. This codifies the hostname shape the cluster has actually run on for ≥51 days and removes the silent divergence between `cluster/config.env` (which previously used asset-style names that no live node would respond to) and the running cluster.

## Context and Problem Statement

Prior to this ADR, `cluster/config.env` declared `CP_NODES="TDNHQ-TLOMGT01:… TDNHQ-TLOMGT02:…"` and `WORKER_NODES="TDNHQ-TLOWRK01:… TDNHQ-TLOWRK02:…"`. The per-node patch filenames matched (`cluster/patches/TDNHQ-TLOMGT01.yaml`, etc.). [README.md](../../../README.md) and repository guidance used the same asset-style names. The live cluster, however, has been running for ≥51 days with Talos hostnames `cp1`, `cp2`, `cp3`, `w1`, `w2`, `w3` — confirmed by `talosctl get hostnamestatus -o jsonpath='{.spec.hostname}'` against all six nodes on 2026-05-25 and by `kubectl get nodes`, which reports those same names as the Kubernetes node identities.

The asset-style names in the repo therefore did not match any live node. `scripts/generate.sh` lowercases the patch filename and writes it into `HostnameConfig.hostname`, so a `make apply` from the prior repo state would have renamed every node from `cp1` to `tdnhq-tlomgt01` (and so on), invalidating client kubeconfigs that target nodes by name and cycling every workload's affinity/toleration that names a node. This is a hostname-rename storm masquerading as a routine apply.

Two options resolve it: rename the live cluster up to the asset-style names, or rename the repo down to the short names. The cluster's name set has been stable for weeks, is referenced from every kubeconfig in use today, and matches the convention common in published Talos / Kubernetes documentation for compact clusters. Renaming the cluster up to assert the inventory style would burn an apply-storm of production disruption to recover a convention only the inventory file uses. Renaming the repo down is a pure declarative change with no operational disruption.

## Decision Drivers

1. **No production disruption on next apply.** The next `make apply` must be a hostname no-op against the live cluster.
2. **Single source of truth for node identity.** Whatever names appear in `cluster/config.env`, `cluster/patches/`, kubeconfigs, and `kubectl get nodes` MUST be the same set.
3. **Inventory cross-reference is preserved.** The site-level asset-style names (`TDNHQ-TLOMGT0N`, `TDNHQ-TLOWRK0N`) still exist in physical-asset spreadsheets and DHCP/DNS reservations; the repo retains a single place to look up that mapping.
4. **Reversibility cost.** A future rename back to asset-style names would require a coordinated apply and kubeconfig refresh; choose the shape with the lower future-reversal cost.

## Considered Options

1. **Rename the repo to match the live cluster (short names).**
2. **Rename the live cluster to match the repo (asset-style names).**
3. **Run kubelet with `--hostname-override` so K8s sees short names while Talos keeps asset-style names.**
4. **Leave the divergence in place and accept that `make apply` is a destructive operation no one should ever run.**

## Decision Outcome

Chosen option: **Option 1, rename the repo to match the live cluster.**

`cluster/config.env` is rewritten to use `cp1`, `cp2`, `cp3`, `w1`, `w2`, `w3` as the inventory keys. Per-node patches are renamed to `cluster/patches/cp1.yaml` … `cluster/patches/w3.yaml`. The Talos hostname written by `scripts/generate.sh` (lowercased from the patch filename) therefore matches the live `HostnameConfig.hostname` on every node, and `make apply` becomes a hostname no-op against the running cluster.

The `systems` file is updated to retain the asset-name ↔ short-name mapping as the single place that records both identities. Any future hardware-asset audit can be reconciled from that file without touching cluster operations.

## Pros and Cons of the Options

### Option 1: Rename the repo to match the live cluster (chosen)

- **Good, because** `make apply` becomes hostname-safe against the live cluster on day one.
- **Good, because** kubeconfigs, dashboards, and any documentation that already names `cp1`/`w1`/etc. remain valid.
- **Good, because** short names align with the convention common in Talos and Kubernetes ecosystem docs.
- **Neutral, because** asset-style names are preserved in `systems` as a cross-reference.
- **Bad, because** the asset-style naming convention used by the site's broader inventory is no longer the primary identifier in this repo.

### Option 2: Rename the live cluster to match the repo

- **Bad, because** it forces a coordinated apply across all six nodes solely to recover a naming convention, with no operational benefit.
- **Bad, because** every kubeconfig that targets a node by name (kubectl context entries, automation scripts, dashboards) must be reissued the same day.
- **Bad, because** workloads with `nodeAffinity` / `nodeSelector` referencing the current names break until the rename completes.

### Option 3: Use `--hostname-override`

- **Good, because** Talos hostnames stay aligned with site-level asset naming.
- **Bad, because** it adds a layer of indirection where the Talos hostname and the K8s node name intentionally differ; future debugging must always remember to translate.
- **Bad, because** changing kubelet flags is a behavior change on a running cluster that this ADR explicitly wants to avoid.

### Option 4: Leave the divergence in place

- **Bad, because** the repo silently misrepresents reality, which is exactly the failure mode that produced this ADR.
- **Bad, because** any agent or human running `make apply` without first reading every file in detail triggers a rename storm.

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Inventory shape.** `cluster/config.env` `CP_NODES` and `WORKER_NODES` MUST use short-name keys (`cp1`–`cp3`, `w1`–`w3`). The corresponding patch filenames under `cluster/patches/` MUST use the same identifiers.
2. **Hostname round-trip.** The Talos hostname installed by `scripts/generate.sh` (lowercased patch filename) MUST equal the `spec.hostname` returned by `talosctl get hostnamestatus` on the live cluster. A reviewer SHOULD spot-check this with `talosctl --nodes <ip> get hostnamestatus` before merging any PR that adds or renames a node.
3. **Inventory cross-reference.** The `systems` file MUST list both the short name and the asset-style name (`TDNHQ-TLO*`) for every node so the mapping is retrievable from a single place.
4. **No `--hostname-override`.** Per-node patches MUST NOT set `kubelet.extraArgs.hostname-override`. If a future ADR overturns this decision, it MUST be a superseding repo-tier ADR.

## Consequences

### Positive

- `make apply` is hostname-safe against the live cluster on the next run.
- The repo, kubeconfigs, dashboards, and node-affinity policies all reference the same set of names.
- The hostname-rename storm that the prior repo state would have triggered is averted.

### Negative

- Asset-style names are no longer the primary identifier in code paths that operate on the cluster. Site-level inventory cross-reference now lives only in `systems`.
- A future decision to switch to a different naming convention (e.g., longer FQDNs once a cluster-internal DNS zone exists) requires a coordinated rename across `cluster/config.env`, patches, kubeconfigs, and any external references — same as today, just with the short names as the starting point.

### Neutral

- Renaming patch files is a pure-declarative repo change; the live cluster is not touched by this ADR.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. Talos `HostnameConfig.hostname` remains the authoritative hostname source in the Talos config format used by this repository's `scripts/generate.sh`.
2. The site-level physical-asset inventory continues to use the `TDNHQ-TLO*` form, so a cross-reference in `systems` remains valuable.
3. No external system requires the Talos node hostname to be the FQDN form `TDNHQ-TLOMGT01.tdnhq.local` (or similar). If one appears, a superseding ADR is required.

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

The PR that introduces this ADR also renames `cluster/patches/TDNHQ-TLOMGT0N.yaml` → `cluster/patches/cp{1,2,3}.yaml`, renames `cluster/patches/TDNHQ-TLOWRK0N.yaml` → `cluster/patches/w{1,2,3}.yaml`, rewrites `cluster/config.env` `CP_NODES` / `WORKER_NODES` / `BOOTSTRAP_NODE`, updates `cluster/patches/controlplane.yaml` certSANs to include the third CP, and refreshes `README.md`, `systems`, and `.gitignore`.

## Related ADRs

- [ADR-0001 (org)](../org/0001-use-architecture-decision-records.md) — defines the ADR format used here.
- [ADR-0003 (repo)](0003-repo-as-cluster-source-of-truth.md) — the process-tier decision that explains why divergences like this one must be detected before they age 38+ days.

## Compliance Notes

This ADR records a naming-policy decision with no direct security control impact. Hostname stability is incidentally a hardening property (kubeconfigs, RBAC RoleBindings tied to node names, and audit logs all become more brittle when hostnames change), but no specific framework control is claimed.
