# Tenant namespace template

These files are the security envelope that every `deploy-*` tenant namespace
should be wrapped in **before** workloads land. They are templates — the
literal placeholder `__TENANT_NAMESPACE__` is substituted by the tenant-
onboarding flow before apply.

The contract is enforced at three layers:
1. **Pod Security Admission** — `restricted` enforce blocks pods that don't
   meet the strict profile (no `allowPrivilegeEscalation`, must `runAsNonRoot`,
   `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, no host*).
2. **NetworkPolicy default-deny** — workloads start with NO connectivity
   beyond explicitly-allowed flows.
3. **NetworkPolicy allow-list** — only DNS and (optionally) Gateway ingress
   are pre-allowed; tenants add per-workload allows for any other flow.

## What's in this template

| File | Purpose |
|---|---|
| `namespace.yaml.tmpl` | Namespace with PSS restricted labels + `nwarila.io/tenant: "true"` |
| `networkpolicy-default-deny.yaml.tmpl` | Block ALL ingress and egress for every pod in the namespace |
| `networkpolicy-allow-dns.yaml.tmpl` | Allow egress to `kube-system/kube-dns:53` (every workload needs DNS) |
| `networkpolicy-allow-gateway-ingress.yaml.tmpl` | Allow ingress from Cilium Gateway proxy pods (omit if internal-only) |

## What tenants commonly add per workload

These are not in the base template because they're workload-specific:

- **Egress to image registries** (for image pulls — required for any new
  workload, but image pulls happen at the kubelet level, not pod level, so
  *usually* not needed as a NetworkPolicy. Verify with the tenant's image
  source.)
- **Egress to the Kubernetes API** (only if the workload uses
  InClusterConfig — e.g., operators, controllers, sidecars that read CRs).
  Allow egress to `10.96.0.1:443` (the `kubernetes` Service ClusterIP) or
  use Cilium's `toServices` extension.
- **Egress to other tenant namespaces** (if cross-tenant API calls — rare;
  prefer service-mesh patterns).
- **Egress to Longhorn data plane** (for PVC consumers, this is typically
  abstracted by the volume mount and doesn't need an explicit NetworkPolicy).

## How tenants get this applied (future)

Step 6 of the platform roadmap (tenant onboarding GitHub Action) will:
1. Detect new `deploy-*` repos in the `nwarila-platform` org
2. Copy this template directory into `clusters/talos-cluster/tenants/<repo>/`
3. Substitute `__TENANT_NAMESPACE__` → `deploy-<repo-name>`
4. Open a PR to add the per-tenant directory to Flux's tracked sources
5. After merge, Flux applies the template, creating the hardened envelope

Until that automation is in place, tenants are onboarded manually by:
1. `cp -r clusters/talos-cluster/tenants/_template clusters/talos-cluster/tenants/deploy-myapp`
2. `sed -i 's/__TENANT_NAMESPACE__/deploy-myapp/g' clusters/talos-cluster/tenants/deploy-myapp/*.yaml.tmpl`
3. `rename .yaml.tmpl .yaml clusters/talos-cluster/tenants/deploy-myapp/*.yaml.tmpl` (or equivalent)
4. Add a `kustomization.yaml` listing the resources
5. Add the new tenant directory to `clusters/talos-cluster/apps/` (or wherever Flux tracks it)

## Pre-flight checks for tenant workloads

Before deploying a workload into a tenant namespace, the tenant repo's
manifests should:

- Set `securityContext.runAsNonRoot: true` and `runAsUser: <non-zero>`
- Set `securityContext.allowPrivilegeEscalation: false`
- Set `securityContext.capabilities.drop: [ALL]`
- Set `securityContext.seccompProfile.type: RuntimeDefault`
- For containers needing a writable filesystem: use `emptyDir` volumes,
  not `readOnlyRootFilesystem: false`
- Test against PSS restricted locally:
  `kubectl run --dry-run=server -n deploy-myapp -i ...`

If a workload genuinely requires elevated privileges (e.g., privileged
pod for system-level operations), request a per-namespace exemption via:
- ADR-0009 amendment in `docs/decision-records/repo/`
- Explanation of why baseline/restricted is insufficient
- Reviewer approval

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Cilium Gateway API + NetworkPolicy](https://docs.cilium.io/en/v1.19/network/servicemesh/gateway-api/)
- [ADR-0009](../../../docs/decision-records/repo/0009-stig-cis-compliance-baseline.md) — the compliance baseline this template implements
