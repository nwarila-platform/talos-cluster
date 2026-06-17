# Migrate The First VSO Secret

This runbook is the first-consumer plan for ADR-0015. It is not an instruction
to run live Vault or cluster commands during a docs-only change.

Use it after VSO has been installed, the generated tenant auth envelope exists,
and the owner has approved the live Vault Kubernetes-auth and KV setup.

## Candidate Decision

The 2026-06-13 survey found no suitable existing tenant SOPS secret to migrate.
Every encrypted Secret currently in the estate is cluster-owned:

| Secret | Location | Decision |
| --- | --- | --- |
| `vault-ra-cert` | `clusters/talos-cluster/apps/vault-aws-access/` | Do not migrate. It is Vault's KMS auto-unseal secret-zero. |
| `vault-serving-cert` | `clusters/talos-cluster/apps/vault-tls/` | Do not migrate. It breaks Vault's TLS cold-start loop and must stay protected-side durable. |
| `talos-reader-talosconfig` | `clusters/talos-cluster/apps/talos-drift/` | Do not migrate first. It is a platform Talos API credential, not an ordinary tenant app secret. |
| `nwarila-runner-registrar` | `clusters/talos-cluster/apps/actions-runner-controller/scale-set/` | Do not migrate first. It controls the GitHub runner control plane. |

The first proof should therefore be a minimal tenant demo, for example
`deploy-vso-smoke`, with a non-production placeholder value. The first real app
migration should wait for a low-criticality tenant secret outside all
bootstrap, recovery, CI control-plane, and Vault startup paths.

## Prerequisites

- VSO CRDs and controller are installed through talos-cluster and healthy.
- The VSO controller connects to Vault over HTTPS using the internal CA.
- The tenant namespace has a generated `vso-sync` ServiceAccount and generated
  `VaultAuth`.
- The generated tenant reconciler can create `VaultStaticSecret` resources but
  still cannot create core Kubernetes `Secret` objects.
- Vault Kubernetes auth is configured with an owner-approved TokenReview
  reviewer identity.
- Vault has a KV-v2 mount named `kv`.
- Vault has a tenant role and policy:

  ```text
  role:   k8s-<tenant-namespace>-vso
  policy: kv-<tenant-namespace>-read
  bound_service_account_names:      ["vso-sync"]
  bound_service_account_namespaces: ["<tenant-namespace>"]
  allowed path prefix: kv/<tenant-namespace>/*
  ```

## Demo Proof Path

Use this if there is still no suitable real tenant SOPS secret.

1. Create a `deploy-vso-smoke` repo with the standard
   `kubernetes/overlays/talos-cluster/kustomization.yaml` deploy-repo contract.
   The workload should be non-exposed and should not print the secret.

2. In Vault, write a non-production value:

   ```bash
   vault kv put kv/deploy-vso-smoke/smoke token='<non-production-placeholder>'
   ```

3. In the tenant repo, add a `VaultStaticSecret`:

   ```yaml
   apiVersion: secrets.hashicorp.com/v1beta1
   kind: VaultStaticSecret
   metadata:
     name: smoke-secret
   spec:
     vaultAuthRef: vso-kubernetes
     mount: kv
     type: kv-v2
     path: deploy-vso-smoke/smoke
     refreshAfter: 1h
     destination:
       create: true
       name: smoke-secret
   ```

4. Point the demo workload at `secretRef.name: smoke-secret`. It should only
   test that the value exists, for example by requiring an environment variable
   at startup and then sleeping. Do not echo the value.

5. Open and merge the tenant PR only after the VSO capability and Vault role are
   already live.

6. Verify VSO status and destination Secret creation:

   ```bash
   kubectl -n deploy-vso-smoke get vaultstaticsecret smoke-secret
   kubectl -n deploy-vso-smoke get secret smoke-secret
   kubectl -n deploy-vso-smoke get deploy,pod
   ```

7. Verify the synced value byte-matches the Vault source without printing it:

   ```bash
   vault kv get -field=token kv/deploy-vso-smoke/smoke > .s3/vso-smoke-vault-token
   kubectl -n deploy-vso-smoke get secret smoke-secret \
     -o jsonpath='{.data.token}' | base64 -d > .s3/vso-smoke-k8s-token
   cmp .s3/vso-smoke-vault-token .s3/vso-smoke-k8s-token
   rm -f .s3/vso-smoke-vault-token .s3/vso-smoke-k8s-token
   ```

8. Prove the honest outage mode during a controlled test window, if approved:
   make Vault temporarily unreachable to VSO without deleting the destination
   Secret. Existing Secret-backed pods should keep their cached Kubernetes
   Secret, while VSO status should show sync degradation. Restore Vault access
   and confirm sync recovers.

## Real SOPS-To-VSO Migration Path

Use this once a low-risk tenant already has a SOPS-managed Secret. Do not use it
for bootstrap, recovery, Vault startup, Talos API, or CI control-plane
credentials.

1. Pick the candidate and record why it is safe:

   ```text
   namespace:
   existing SOPS Secret:
   consuming workload:
   blast radius:
   rollback owner:
   why this is not bootstrap/recovery-critical:
   ```

2. Decrypt the current SOPS Secret only into an ignored local path such as
   `.s3/vso-migration/`. Never commit the decrypted file.

3. Write each key to Vault KV under the tenant prefix. Preserve exact bytes,
   including trailing newlines when they are part of the value:

   ```bash
   vault kv put kv/<tenant-namespace>/<app>/<secret-name> \
     key1=@.s3/vso-migration/key1 \
     key2=@.s3/vso-migration/key2
   ```

4. Add a `VaultStaticSecret` in the tenant repo with a temporary destination
   name, for example `<existing-secret>-vso`. Do not let SOPS/Flux and VSO
   manage the same Kubernetes Secret name at the same time.

5. Merge the tenant PR and wait for VSO to create the temporary destination
   Secret.

6. Compare every key from the existing SOPS Secret and the VSO-created Secret
   without printing values:

   ```bash
   mkdir -p .s3/vso-migration/compare

   kubectl -n <tenant-namespace> get secret <existing-secret> \
     -o jsonpath='{.data.key1}' | base64 -d > .s3/vso-migration/compare/sops-key1

   kubectl -n <tenant-namespace> get secret <existing-secret>-vso \
     -o jsonpath='{.data.key1}' | base64 -d > .s3/vso-migration/compare/vso-key1

   cmp .s3/vso-migration/compare/sops-key1 .s3/vso-migration/compare/vso-key1
   rm -rf .s3/vso-migration/compare
   ```

7. Cut the workload over in a second tenant PR:

   - change `secretRef`, `envFrom`, or volume references from
     `<existing-secret>` to `<existing-secret>-vso`;
   - roll one replica or one low-risk component first when the app supports it;
   - watch startup, readiness, and application logs without printing secrets.

8. Keep the old SOPS Secret in place through one observation window. During that
   window, rollback is a tenant PR that points the workload back to the SOPS
   Secret.

9. Retire the SOPS Secret only after the observation window passes:

   - remove it from the tenant kustomization;
   - remove the encrypted SOPS file;
   - keep the Vault KV value;
   - record the migration in the tenant PR.

10. After retirement, rollback is still possible:

    - restore the last encrypted SOPS Secret from Git history;
    - point the workload back to that Secret;
    - suspend or remove the `VaultStaticSecret`;
    - leave the Vault KV value in place until the rollback window closes.

## Verification Checklist

- `VaultStaticSecret` reports ready or synced status.
- The destination Kubernetes Secret exists in the tenant namespace.
- Each key byte-matches the Vault source or former SOPS source.
- The consuming workload uses the VSO destination Secret.
- No secret value appears in Git, PR comments, CI logs, pod logs, or terminal
  history pasted into an issue.
- Tenant reconciler still cannot create core Kubernetes `Secret`, `Role`, or
  `RoleBinding` objects.
- A Vault outage affects new sync/rotation, not already-running pods with an
  existing cached Kubernetes Secret.

## Rollback Guardrails

- Do not delete the Vault KV value during the initial rollback window.
- Do not delete the old SOPS Secret until the cutover has passed its observation
  window.
- Do not use the same destination Secret name with both SOPS and VSO at once.
- If VSO or Vault auth is unhealthy, rollback the tenant workload reference
  first. Debug the operator after the app is stable.
- If the problem is the platform capability, rollback through the owner-gated
  talos-cluster PR that installed or configured VSO.

## Owner-Gated Items

- Choose and pin the VSO chart/controller version after verifying support for
  the cluster's Kubernetes version.
- Decide the Vault Kubernetes auth TokenReview reviewer identity and RBAC.
- Decide whether generated VSO auth envelopes are created for all deploy
  tenants or only for an explicit allowlist.
- Approve the first real tenant secret candidate after the demo proof.
- Add admission policy that constrains tenant `VaultStaticSecret` objects to
  the generated auth ref, `kv` mount, KV-v2 type, and namespace-prefixed path.
