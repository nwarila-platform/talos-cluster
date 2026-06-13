# Herowars Source Auth

`herowars` tracks the private
`the-hero-wars-guys/ubi9-herowars-engine-porter` repository through Flux.
The generated `GitRepository` references `secretRef.name: herowars-git-auth`
in the `herowars` namespace. No credential is committed here.

The committed source URL is SSH:

```text
ssh://git@github.com/the-hero-wars-guys/ubi9-herowars-engine-porter.git
```

The owner must supply a SOPS-encrypted Kubernetes `Secret` named
`herowars-git-auth` in namespace `herowars` with Flux SSH auth keys:

- `identity`: private deploy key with read access to the repository.
- `identity.pub`: matching public key.
- `known_hosts`: GitHub SSH host key entry.

If the owner chooses a PAT instead, change
`DEPLOY_REPO_URL_OVERRIDES["herowars"]` to the HTTPS repository URL and use Flux
HTTPS auth keys (`username` and `password`) in the same Secret name.

## Vault Workload Identity

The app repository should create `ServiceAccount/engine-porter` in namespace
`herowars`, matching the Step 72 Vault Kubernetes-auth role. The talos-cluster
tenant envelope creates only the Flux `deploy-reconciler` ServiceAccount/RBAC.

Audience hardening should be done as a paired app/Vault change: add an audience
to the app's projected token request and the matching Vault Kubernetes-auth
role, then test login before rollout.
