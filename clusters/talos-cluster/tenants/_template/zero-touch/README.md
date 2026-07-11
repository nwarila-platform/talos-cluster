# Zero-touch tenant envelope template

This is the Phase 2 reusable source for tenant cluster-side envelopes. It uses
Kustomize because this repository is already reconciled and validated as a
Kustomize tree by Flux, and the rendered output stays as reviewable Kubernetes
manifests. Helm would add a second rendering model for simple cluster plumbing.

The `render_overlay()` function in `scripts/sync-deploy-repos.sh` consumes
`base/` today when it emits tenant overlays (#187). The examples are proof
inputs only; do not apply them directly.

## Contract

A tenant render is admitted from a reviewed contract:

- `tenantId`: immutable namespace and Vault tenant ID
- `org`: allowed GitHub organization
- `deployRepo`: allowed deploy repository in that organization

The GitRepository URL is derived from `org` and `deployRepo`; it is not an input.
The Flux branch is fixed to `main`, the deploy path is fixed to
`./kubernetes/overlays/talos-cluster`, and the GitHub App secret name is derived
by convention. A future Phase 3 registry/generator should enforce the allowlist
mechanically. For Phase 2, the source-controlled allowlist below is the reviewed
contract:

- `contracts/allowed-deploy-repos.yaml`

## Render herowars proof

```sh
kubectl kustomize clusters/talos-cluster/tenants/_template/zero-touch/examples/herowars
```

The rendered object set is defined by `base/kustomization.yaml`; the Herowars
proof currently renders these envelope categories:

- tenant namespace with PSS restricted labels and `nwarila.io/tenant: "true"`
- ServiceAccounts defined by the platform base template: `vault-client` as the
  Vault-auth identity, `vso-org-pull-<org-prefix>`, and `deploy-reconciler`
- `deploy-reconciler` Role and RoleBinding with no ServiceAccount write authority
- `vault-ca` ConfigMap
- default-deny, DNS egress, and Vault egress NetworkPolicies, plus the
  `allow-dns-visibility` DNS-visibility CiliumNetworkPolicy
- GitRepository and Flux Kustomization for the deploy repo
- VSO VaultStaticSecrets for `ghcr-pull` and `<tenant>-gitops-source-auth`

The `vault-client: "true"` pod label used by the Vault egress policy is network
plumbing only. Vault Kubernetes auth and Vault policies are the security
boundary.
