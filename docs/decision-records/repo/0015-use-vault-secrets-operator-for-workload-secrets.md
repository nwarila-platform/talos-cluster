# ADR-0015: Use Vault Secrets Operator for Workload Secrets

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-13                              |
| Authors        | Nick Warila (@NWarila), Codex           |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | Step 66 TASK.md, PLAN trust-root invariant, rancher-terraform-framework ADR-repo/0004, rancher-terraform-framework `vault-secrets.yaml`, deploy-vault ADR-0008/0009/0011/0013 |
| Informed       | Claude, future deploy-* maintainers, future platform operators |
| Reversibility  | Medium                                  |
| Review-by      | 2026-12-13                              |

## TL;DR

Install HashiCorp Vault Secrets Operator (VSO) as a one-time cluster
capability, then let tenant `deploy-*` repositories consume Vault KV-v2 secrets
through `VaultStaticSecret` resources. `talos-cluster` owns the operator,
cluster/network/RBAC capability, and generated tenant auth boundary. Tenant
repositories own their own `VaultStaticSecret` objects and consuming workloads.
Vault remains the source of truth for secret values; Kubernetes Secrets are the
runtime cache.

## Context and Problem Statement

Vault now has the foundation needed to become useful to applications: KMS
auto-unseal, recovery escrow, TLS listener, internal PKI, and Stage-1 backup
design are documented in the deploy-vault and talos-cluster ADRs. It still has
no ordinary secret consumers.

The current application secret path is SOPS in Git, decrypted by Flux through
the `sops-age` key in `flux-system`. That is still the right path for
bootstrap, cold-start, and trust-root material, but it is the wrong long-term
shape for ordinary app credentials. Rotating an app password should not require
a Git secret rewrite and Flux decryption path when Vault can own the value and
VSO can materialize a namespaced runtime Secret.

The portfolio already has an organization pattern for this problem:
`rancher-terraform-framework` ADR-repo/0004 chooses Vault references plus VSO
so Terraform and Helm receive references rather than raw secret values. Its
`charts/platform-workload/templates/vault-secrets.yaml` renders
`VaultStaticSecret` objects from tenant-provided Vault references. This cluster
should use the same mechanism, adapted to the talos-cluster trust-root split.

The trust-root invariant is the hard boundary: `talos-cluster` changes for
shared capabilities and secret-zero/trust-boundary material, not for ordinary
application configuration. VSO must therefore be a cluster capability, while
individual secret references belong with the app manifests in `deploy-*`
repositories.

## Decision Drivers

1. Keep raw app secret values out of Git, Terraform values, Helm values, Flux
   release metadata, CI logs, and rendered tenant manifests.
2. Preserve the trust-root split: cluster repo for the shared capability and
   boundary; tenant repos for app-specific secret references and consumers.
3. Use per-namespace least privilege instead of a shared broad Vault role.
4. Keep consuming workloads Kubernetes-native by presenting ordinary
   Kubernetes Secrets.
5. Make rotation a Vault/VSO operation instead of a Git rewrite.
6. Avoid moving bootstrap or recovery-critical material behind a service that
   depends on the cluster and Vault already being healthy.

## Considered Options

1. HashiCorp Vault Secrets Operator with `VaultStaticSecret`.
2. External Secrets Operator with a Vault `SecretStore`.
3. Vault Agent injector or sidecar templates.
4. Keep using SOPS-only Kubernetes Secrets for all app credentials.
5. Allow tenant repos to author raw Kubernetes Secret manifests.

## Decision Outcome

Chosen option: **Option 1, HashiCorp Vault Secrets Operator**.

VSO is the accepted mechanism for in-cluster app secret consumption. It matches
the rancher-terraform-framework pattern, keeps workloads on native Kubernetes
Secrets, and avoids adding a second vendor-neutral abstraction when Vault is the
only intended source of truth.

### Kubernetes 1.36 Risk Acceptance

As of 2026-06-13, talos-cluster runs Kubernetes `v1.36.0` while VSO's published
supported Kubernetes matrix for the selected release is `1.29` through `1.35`.
The first VSO release that explicitly supports Kubernetes `1.36` has no
announced date.

Decision: deploy VSO now on Kubernetes `1.36`, ahead of vendor support. The
owner explicitly accepted this unsupported-version risk on 2026-06-13.

Rationale: ordinary workload secrets need a Vault consumption path now, and
continuing to add static SOPS-managed app Secrets would grow the wrong trust
shape. Kubernetes `1.36` is one minor ahead of the supported `1.35` ceiling and
is expected to be ABI-close enough for this controller-class workload, but that
is an accepted risk rather than a vendor guarantee.

Risk: VSO could have subtle incompatibilities with Kubernetes `1.36`, and
HashiCorp support may decline unsupported-matrix issues until a supporting VSO
release exists.

Mitigation: pin VSO chart/image version `1.4.0`, watch controller health after
Flux deploys it, and upgrade to the first release that lists Kubernetes `1.36`
support. The blast radius is contained: a VSO outage stops future secret sync
and rotation, but already-running pods holding cached Kubernetes Secrets do not
immediately lose those Secret values.

### Cluster Capability

The first implementation adds VSO as a talos-cluster app under
`clusters/talos-cluster/apps/vault-secrets-operator/`. The implementation is
owner-gated because merging the app installs CRDs/controllers into the live
cluster through Flux.

The operator must connect to Vault over the TLS listener, not a plaintext
bootstrap path. Its Vault connection must trust the internal CA used by
deploy-vault ADR-0013 and should target a stable HTTPS Vault service name such
as `https://vault.deploy-vault.svc.cluster.local:8200`, provided that name is
present in the serving certificate SAN set.

The VSO controller namespace needs only the egress required to reach:

- the Kubernetes API;
- DNS;
- the Vault HTTPS service.

Tenant workload pods do not receive Vault egress by default. VSO performs the
sync and writes the Kubernetes Secret cache.

### Tenant Auth Boundary

The cluster repo owns the generated tenant auth envelope because it is the
boundary that decides which Kubernetes namespaces may authenticate to Vault.
This should be generated by the existing deploy-repo sync path rather than
hand-authored per app.

For each admitted `deploy-*` tenant that is allowed to consume Vault secrets,
the generated tenant envelope should include:

- a dedicated ServiceAccount such as `vso-sync`;
- a namespaced `VaultAuth` that uses Kubernetes auth and the `vso-sync`
  ServiceAccount;
- no tenant permission to create or mutate `VaultAuth` or `VaultConnection`.

Tenant deploy repos own only their `VaultStaticSecret` resources and workloads.
The generated `deploy-reconciler` Role must therefore be extended only for the
VSO namespaced secret-reference CRDs that tenants are allowed to author. The
initial permission should be `secrets.hashicorp.com/vaultstaticsecrets`; do not
restore tenant permission to create core Kubernetes `secrets`, `roles`, or
`rolebindings`.

This creates the intended split:

| Owner | Responsibility |
| --- | --- |
| `talos-cluster` | VSO install, controller/network policy, CRD ordering, generated tenant `vso-sync` ServiceAccount and `VaultAuth`, generated RBAC allowing tenant `VaultStaticSecret` objects, and any admission policy that restricts VSO references. |
| Live Vault ops | Kubernetes auth method, TokenReview/reviewer identity, KV-v2 mount, per-tenant Vault roles, and policies. |
| `deploy-*` tenant repo | `VaultStaticSecret` objects, secret path references, destination Secret names, and consuming workload references. |

### Vault Auth Model

Use Vault's Kubernetes auth method. A namespace-specific ServiceAccount JWT
authenticates to a namespace-specific Vault role. The role attaches a
least-privilege policy scoped to that namespace's KV prefix.

Default convention:

| Item | Convention |
| --- | --- |
| Kubernetes ServiceAccount | `<tenant-namespace>:vso-sync` |
| Generated VaultAuth name | `vso-kubernetes` |
| Vault Kubernetes auth mount | `kubernetes-talos/` unless an implementation ADR chooses another name |
| Vault role | `k8s-<tenant-namespace>-vso` |
| Vault policy | `secret-<tenant-namespace>-read` |
| Allowed secret prefix | `secret/<tenant-namespace>/*` |

The Vault role must bind both `bound_service_account_names=["vso-sync"]` and
`bound_service_account_namespaces=["<tenant-namespace>"]`. Do not create a
shared "all tenants" role or wildcard namespace binding.

Policy starts read-only:

```hcl
path "secret/data/<tenant-namespace>/*" {
  capabilities = ["read"]
}

path "secret/metadata/<tenant-namespace>/*" {
  capabilities = ["read"]
}
```

Do not grant `create`, `update`, `delete`, `sudo`, or broad `list` for the
first static-secret use case. If VSO needs additional metadata capabilities for
a specific feature, add the narrowest capability in the implementation PR and
record why.

### Secrets Engine and Path Convention

Use a KV-v2 mount named `secret` for ordinary workload secrets unless a later ADR
chooses a more specific mount split. VSO references use:

- `mount: secret`
- `type: kv-v2`
- `path: <tenant-namespace>/<app-or-component>/<secret-name>`

Example:

```yaml
apiVersion: secrets.hashicorp.com/v1beta1
kind: VaultStaticSecret
metadata:
  name: app-config
spec:
  vaultAuthRef: vso-kubernetes
  mount: secret
  type: kv-v2
  path: deploy-keycloak/internal/admin
  refreshAfter: 1h
  destination:
    create: true
    name: keycloak-admin
```

The namespace prefix is load-bearing. Admission policy should eventually reject
tenant `VaultStaticSecret` objects whose `spec.path` does not begin with the
object namespace.

### Failure Mode

VSO sync adds a Vault availability dependency at sync time.

Once VSO has created a destination Kubernetes Secret, already-running pods and
new pods that can read that existing Secret do not instantly fail just because
Vault is briefly unavailable. However:

- a brand-new namespace or first sync cannot create its Secret while Vault is
  unreachable;
- rotations pause while Vault, Kubernetes auth, or the VSO controller is
  unhealthy;
- deleting the cached Kubernetes Secret during a Vault outage can turn an
  outage into an app startup failure;
- restoring a cluster from backups may require Vault to be healthy before VSO
  can recreate app Secrets that were not present in restored etcd state.

For that reason, never move bootstrap, cold-start, or recovery-critical
material behind VSO. Excluded material includes the SOPS age key, Talos
`secrets.yaml`, talosconfig/kubeconfig recovery material, Vault's IAM Roles
Anywhere certificate, Vault's listener TLS Secret, Vault recovery/root escrow,
and any credential needed to start or unseal Vault itself.

The first migrations must be Vault-up-tolerant and low blast radius.

### First Migration Candidate

The current estate has no suitable existing tenant SOPS secret to migrate.
Read-only survey on 2026-06-13 found SOPS files only in `talos-cluster`:

| Secret | Why it is not the first VSO migration |
| --- | --- |
| `vault-ra-cert` | Vault KMS auto-unseal secret-zero. It is explicitly excluded from VSO. |
| `vault-serving-cert` | Durable Vault TLS bootstrap Secret. Moving it behind Vault would recreate a cold-start loop. |
| `talos-reader-talosconfig` | Platform Talos API credential for drift checking, not an ordinary tenant app secret. |
| `nwarila-runner-registrar` | Platform CI control-plane credential for runner provisioning, not a low-risk tenant secret. |

Because none is suitable, the first proof should be a minimal demo tenant such
as `deploy-vso-smoke`, created only to prove VSO wiring. It should use a
non-production placeholder value stored in Vault KV, a `VaultStaticSecret` in
the tenant repo, and a tiny non-exposed workload that consumes the resulting
Kubernetes Secret without printing it.

The first real application migration should wait until a tenant app has a
low-criticality secret that is not in any bootstrap, recovery, CI control-plane,
or Vault startup path.

### Phased Rollout

1. **Design, this ADR.** Complete.
2. **Capability PR, owner-gated live cluster change.** Install VSO CRDs and
   controller through Flux, with TLS trust and controller egress. Do not add
   tenant `VaultStaticSecret` objects in the same PR unless CRD ordering is
   already proven.
3. **Boundary PR, owner-gated live cluster change.** Update the generated
   deploy-repo tenant envelope to include the standard `vso-sync` ServiceAccount
   and generated `VaultAuth`, and extend the generated `deploy-reconciler` Role
   only for allowed VSO CRDs. Because the current root Kustomization aggregates
   `apps` and `tenants` together, do this after VSO CRDs exist, or split Flux
   Kustomizations with an explicit dependency.
4. **Vault live ops, owner-gated.** Enable/configure Kubernetes auth, decide the
   TokenReview reviewer identity, enable or confirm the `secret` KV-v2 mount, and
   create the first namespace role/policy. No raw app values go through Git.
5. **First consumer PR, owner-gated tenant change.** Add `deploy-vso-smoke` or
   the first approved tenant `VaultStaticSecret` and workload reference. Verify
   the synced Kubernetes Secret before cutting over any real app.
6. **Expansion.** Add tenants one at a time. Add admission policy that enforces
   `mount: secret`, the generated `vaultAuthRef`, namespace-prefixed paths, and no
   direct core Secret manifests from tenant repos.

## Pros and Cons of the Options

### Option 1: Vault Secrets Operator (chosen)

- **Good, because** it matches the already accepted rancher framework pattern.
- **Good, because** workloads consume native Kubernetes Secrets without app code
  changes.
- **Good, because** Vault rotation can update the runtime cache without a Git
  secret rewrite.
- **Bad, because** VSO becomes another cluster controller and CRD lifecycle to
  monitor.
- **Bad, because** tenant RBAC and admission must explicitly allow only the VSO
  reference surface, not raw Kubernetes Secrets.

### Option 2: External Secrets Operator

- **Good, because** ESO is broadly used and supports many providers.
- **Bad, because** the organization already has a VSO pattern and Vault is the
  intended provider. ESO would introduce a second abstraction without a current
  multi-provider requirement.

### Option 3: Vault Agent injector or sidecars

- **Good, because** it can avoid Kubernetes Secret objects for some workloads.
- **Bad, because** it changes pod shape, adds sidecars or mutation behavior,
  complicates restricted Pod Security review, and is less convenient for apps
  that already expect Kubernetes Secret references.

### Option 4: SOPS-only for all app secrets

- **Good, because** it is already working for bootstrap and protected-side
  cluster material.
- **Bad, because** it keeps ordinary app rotation coupled to Git, SOPS, and
  Flux decryption.

### Option 5: Tenant-authored raw Kubernetes Secrets

- **Good, because** Kubernetes workloads can consume them directly.
- **Bad, because** raw values land in tenant Git, rendered manifests, CI logs,
  or Helm/Flux metadata. This remains rejected.

## Consequences

### Positive

- Vault gets its first clear workload-consumption path.
- Tenant repos can own app-specific secret references without giving them core
  Secret write permission.
- The trust root continues to change for shared capability and boundaries, not
  for ordinary app secrets.
- The first proof can be deliberately low-risk instead of touching Vault's own
  startup or recovery material.

### Negative

- Installing VSO is a real live-cluster change and must be staged with CRD
  ordering in mind.
- Vault Kubernetes auth setup needs an owner-approved TokenReview/reviewer
  identity and policies before any tenant can sync.
- VSO creates Kubernetes Secrets as a cache, so etcd still contains runtime app
  secret values after sync. This design removes raw values from Git and
  IaC/release inputs; it does not make Kubernetes Secrets disappear.

### Neutral

- SOPS remains correct for trust-root and cold-start material.
- Dynamic database credentials and PKI issuance can be evaluated later; the
  first rollout is KV-v2 static secrets only.

## Confirmation

This ADR is confirmed when:

1. VSO is installed through a reviewed talos-cluster PR with CRDs present before
   any generated tenant `VaultAuth` or tenant `VaultStaticSecret` is applied.
2. The VSO controller reaches Vault only over HTTPS with the internal CA trust.
3. A tenant namespace has a generated `vso-sync` ServiceAccount and generated
   `VaultAuth`; the tenant reconciler can create `VaultStaticSecret` but still
   cannot create core `Secret`, `Role`, or `RoleBinding` objects.
4. Vault has a namespace-specific Kubernetes auth role bound to that namespace
   and ServiceAccount, with read-only policy on the matching KV prefix.
5. The first demo or approved tenant `VaultStaticSecret` syncs a Kubernetes
   Secret whose data matches the source Vault KV value.
6. A simulated Vault outage proves the cached Kubernetes Secret remains present
   while new sync/rotation reports degraded status.

## Assumptions

1. VSO chart/image version `1.4.0` is intentionally deployed on Kubernetes
   `v1.36.0` before VSO lists that minor in its supported matrix. This is not a
   compatibility claim; it is the explicit 2026-06-13 owner risk acceptance
   recorded above.
2. OSS Vault is sufficient for the first rollout. If Vault Enterprise
   namespaces are introduced later, the `VaultConnection`/`VaultAuth` namespace
   fields must be set by policy.
3. The first rollout uses KV-v2 static secrets only. Dynamic secrets and PKI
   secret issuance need separate review.
4. The generated deploy-repo tenant envelope remains the normal path for
   namespace-scoped platform boundaries.

## Supersedes

None.

## Superseded by

None (current).

## Implementing PRs

- This ADR and [`migrate-first-vso-secret.md`](../../runbooks/migrate-first-vso-secret.md)
  define the design and first-migration plan.
- Step 67 installs VSO as an inert cluster capability: CRDs, controller,
  network policy, namespace-local CA trust, and a default `VaultConnection`.
  It does not configure live Vault Kubernetes auth, create tenant
  `VaultStaticSecret` objects, or add tenant secret values.

## Related ADRs

- [ADR-0011](0011-auto-discover-deploy-repositories.md) - defines the
  `deploy-*` app surface and the default tenant reconciler boundary.
- [ADR-0012](0012-vault-kms-auto-unseal-credential-delivery.md) - records the
  protected Vault bootstrap exception in talos-cluster.
- [ADR-0014](0014-use-stage-1-local-backup-server-for-dr.md) - records Vault
  Raft and etcd recovery expectations that VSO consumers depend on.
- deploy-vault ADR-0008/0009/0011 - records KMS auto-unseal, escrow, and the
  corrected shared-file credential delivery model.
- deploy-vault ADR-0013 - records the Vault TLS/PKI foundation VSO must use.
- rancher-terraform-framework ADR-repo/0004 - organization pattern for Vault
  references plus VSO instead of raw Terraform/Helm secret values.

## Compliance Notes

| Framework | Control / Practice ID | Evidence Contribution |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5 | AC-6, IA-5 | Per-namespace Vault roles and policies reduce shared credential scope. |
| NIST SP 800-53 Rev. 5 | SC-28 | Raw app secret values move out of Git and IaC/release inputs; Vault is the source of truth. |
| NIST SP 800-190 | 4.1, 4.4 | Workload secret delivery uses a controlled operator path instead of embedding secrets in images or manifests. |
| SSDF | PO.5, PS.3 | Defines a repeatable app-secret consumption contract with reviewable boundaries. |
