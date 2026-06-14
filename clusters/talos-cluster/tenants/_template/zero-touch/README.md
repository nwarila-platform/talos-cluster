# Zero-touch tenant envelope template

This is the Phase 2 reusable source for tenant cluster-side envelopes. It uses
Kustomize because this repository is already reconciled and validated as a
Kustomize tree by Flux, and the rendered output stays as reviewable Kubernetes
manifests. Helm would add a second rendering model for simple cluster plumbing.

The template is render-only until a future registry/generator phase consumes it.
Do not apply the examples directly.

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
contract Claude audits:

- `contracts/allowed-deploy-repos.yaml`

## Render herowars proof

```sh
kubectl kustomize clusters/talos-cluster/tenants/_template/zero-touch/examples/herowars
```

The render includes:

- tenant namespace with PSS restricted labels and `nwarila.io/tenant: "true"`
- platform-owned `vault-client` ServiceAccount
- default-deny, DNS egress, and Vault egress NetworkPolicies
- `deploy-reconciler` RBAC with no ServiceAccount write authority
- GitRepository and Flux Kustomization for the deploy repo

The `vault-client: "true"` pod label used by the Vault egress policy is network
plumbing only. Vault Kubernetes auth and Vault policies are the security
boundary.
