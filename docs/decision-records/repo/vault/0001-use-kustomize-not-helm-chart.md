# ADR-0001: Use Kustomize, not the Vault Helm chart, for the shell-free image

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-01                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Deploy the UBI9-micro (shell-free) Vault image with **plain Kustomize manifests**.
The official `hashicorp/vault-helm` chart is structurally incompatible with a
shell-free image and cannot be made compatible by any values override.

## Context and Problem Statement

The deployment target is `ghcr.io/nwarila-platform/ubi9-hashicorp-vault`,
which by design has:

- `ENTRYPOINT ["/usr/local/bin/vault"]`, `USER 65532:65532`;
- **no** `/bin/sh`, `/bin/bash`, `dash`, or `busybox` (asserted absent by the
  image's `tests/runtime-hardening.sh`);
- no coreutils (`cp`, `sed`) and no `docker-entrypoint.sh`.

We must choose a rendering tool that respects these constraints.

## Decision Drivers

- The image's hardening (no shell/coreutils) must not be undone to deploy it.
- Manifests must be auditable and digest-pinned.
- The org already uses Kustomize and Flux throughout `talos-cluster`.

## Considered Options

1. **`hashicorp/vault-helm` chart** (HelmRelease via Flux).
2. **Kustomize / raw manifests** (this repo, reconciled by Flux Kustomization).
3. Ship a shell-bearing `compat` image variant just to satisfy the chart.

## Decision Outcome

**Chosen: Option 2 (Kustomize).** The pod spec omits `command:` and sets
`args: ["server", "-config=/vault/config/vault.hcl"]`, letting the image's own
entrypoint run. Config is delivered as a read-only ConfigMap; Kubernetes
downward API values feed `VAULT_RAFT_NODE_ID`, `VAULT_API_ADDR`, and
`VAULT_CLUSTER_ADDR`, which Vault reads directly without shell templating.

### Why not Helm (evidence)

Inspected `hashicorp/vault-helm` at tag `v0.32.0` (appVersion 1.21.2) and `main`:

- `templates/server-statefulset.yaml` hardcodes the server container
  `command: ["/bin/sh", "-ec"]` **unconditionally** — there is no `{{ if }}`
  guard and **no `server.command`/`server.entrypoint` value** to override it.
- The `vault.args` helper (`_helpers.tpl`) renders a shell **script**:
  `cp /vault/config/extraconfig-from-values.hcl /tmp/storageconfig.hcl;` then
  `[ -n "${HOST_IP}" ] && sed -Ei "s|HOST_IP|${HOST_IP?}|g" …`, ending with
  `/usr/local/bin/docker-entrypoint.sh vault server -config=…`. This needs
  `/bin/sh`, `cp`, `sed`, **and** `docker-entrypoint.sh` — none of which exist
  in the UBI9-micro image.
- The default `lifecycle.preStop` is also a shell hook
  (`/bin/sh -c "sleep N && kill -SIGTERM $(pidof vault)"`).

This is independently corroborated by the Docker Hardened Images team
(github.com/orgs/docker-hardened-images/discussions/103), who state their
shell-less Vault image "cannot run" under the chart because `docker-entrypoint.sh`
ships only in shell-bearing `compat` variants "used for helm charts."

Option 3 (compat image) is rejected: it defeats the purpose of the UBI9-micro
image and reintroduces a shell into the runtime.

## Confirmation

The repository validation workflow renders the Kustomize tree (no Helm) and
fails on any tag-pinned image. On-cluster, a pod with no shell must start from
its own entrypoint and answer `/v1/sys/health` — verified per
[`deploy-vault` verification plan](https://github.com/nwarila-platform/deploy-vault/blob/main/docs/reference/verification-plan.md).

## Consequences

### Positive
- The image's hardening is preserved end-to-end.
- Manifests are transparent and digest-pinned; no chart indirection.

### Negative
- We maintain the StatefulSet/Service/config ourselves rather than tracking
  upstream chart improvements.
- Operators cannot `kubectl exec … sh` into Vault pods; admin operations run
  from a separate full Vault CLI pod or via the API.

### Neutral
- Dynamic pod addresses move from shell `sed` to Kubernetes env expansion plus
  Vault's documented address and Raft node ID environment variables.

## Related ADRs

- [ADR-0002](0002-use-ha-raft-integrated-storage.md) — Raft HA topology.
- [ADR-0007](0007-disable-mlock-accept-swap-risk.md) — `disable_mlock` posture.
