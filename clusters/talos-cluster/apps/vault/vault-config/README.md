# Vault config source of truth

This directory records manually applied Vault configuration that is live in the
cluster as source-controlled recovery material. It is intentionally not a
reconciled workload path yet.

## Org-pull foundation (VSO)

These files capture the live Step 121/123 org-pull policies and roles: the
cross-org secret-delivery foundation used by Vault Secrets Operator. They use
the `secret` kv-v2 mount and do not need the Kubernetes auth accessor
placeholder used by tenant read/write policies.

Apply the org-pull foundation:

```sh
vault policy write vso-org-pull-read-hwg clusters/talos-cluster/apps/vault/vault-config/policies/vso-org-pull-read-hwg.hcl
vault policy write vso-org-pull-read-nwp clusters/talos-cluster/apps/vault/vault-config/policies/vso-org-pull-read-nwp.hcl
vault write auth/kubernetes/role/vso-org-pull-hwg @clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles/vso-org-pull-hwg.json
vault write auth/kubernetes/role/vso-org-pull-nwp @clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles/vso-org-pull-nwp.json
```

The tenant role/policies are already applied live and captured here only for
disaster recovery.

Apply the new B-apex source-minter foundation after merge:

```sh
vault policy write source-minter-hwg clusters/talos-cluster/apps/vault/vault-config/policies/source-minter-hwg.hcl
vault write auth/kubernetes/role/source-minter-hwg @clusters/talos-cluster/apps/vault/vault-config/auth/kubernetes/roles/source-minter-hwg.json
```

## Files

| Path | Purpose |
|---|---|
| `policies/vso-org-pull-read-hwg.hcl` | Read-only hwg org-pull credentials policy for VSO |
| `policies/vso-org-pull-read-nwp.hcl` | Read-only nwp org-pull credentials policy for VSO |
| `policies/tenant-read.hcl` | Already-applied / DR capture: tenant read access to its own `provisioned/` bucket |
| `policies/tenant-write.hcl` | Already-applied / DR capture: tenant write access to its own `state/` bucket |
| `policies/source-minter-hwg.hcl` | NEW: apply via `vault policy write source-minter-hwg ...` |
| `auth/kubernetes/roles/vso-org-pull-hwg.json` | Kubernetes auth role for the hwg org-pull VSO service account |
| `auth/kubernetes/roles/vso-org-pull-nwp.json` | Kubernetes auth role for the nwp org-pull VSO service account |
| `auth/kubernetes/roles/tenant.json` | Already-applied / DR capture: Kubernetes auth role for tenant `vault-client` service accounts |
| `auth/kubernetes/roles/source-minter-hwg.json` | NEW: apply via `vault write auth/kubernetes/role/source-minter-hwg ...` |
