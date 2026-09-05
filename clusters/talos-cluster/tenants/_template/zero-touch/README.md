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
- one opt-in CiliumNetworkPolicy per registered tunnel, each permitting only
  that tunnel's proxy to reach pods labelled with its own tunnel name in
  `nwarila.io/tunnel-exposed`, on TCP 8080 only
- GitRepository and Flux Kustomization for the deploy repo
- VSO VaultStaticSecrets for `ghcr-pull` and `<tenant>-gitops-source-auth`

The `vault-client: "true"` pod label used by the Vault egress policy is network
plumbing only. Vault Kubernetes auth and Vault policies are the security
boundary.

For an already-onboarded tenant, publishing an app requires only the pod label
`nwarila.io/tunnel-exposed: <tunnel>` and a `networking.k8s.io/v1` Ingress using
that tunnel's class, an in-zone host, at least one HTTP path, and a numeric
Service backend port of 8080. The platform supplies both sides of the
network-policy contract; the tenant must not add a platform-side route or CNP.

The label value is the tunnel name rather than a boolean, and that is a security
boundary, not a naming preference. An organization may run several tunnels at
different protection tiers over the same tenant namespaces, so namespace scoping
cannot separate them; a Kubernetes label holds one value per key, which makes a
pod reachable from exactly one proxy. A boolean opt-in would let a tenant
republish an mTLS-protected origin through the unauthenticated tunnel by
declaring a second Ingress. `scripts/check-tunnel-isolation.py` fails CI if any
part of that contract drifts.

| Tunnel | Label value | Ingress class | Zone |
|---|---|---|---|
| hwg | `hwg` | `cf-tunnel-hwg` | `theherowarsguys.com` |
| nwp-public | `nwp-public` | `cf-tunnel-nwp-public` | `nicholaswarila.com` (excluding the protected zone) |
| nwp-mtls | `nwp-mtls` | `cf-tunnel-nwp-mtls` | `secure.nicholaswarila.com` |
