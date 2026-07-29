# ADR-0031: Adopt GitHub OIDC JWT Authentication for CI

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-28                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | AR4a rev.2–rev.4 adversarial plan review and owner adjudication |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Use a dedicated Vault JWT auth mount, `jwt-github`, alongside the existing
Kubernetes auth mount. GitHub Actions deploy jobs authenticate with
issuer-signed OIDC identity; later onboarding creates one `deploy-<repo>` role
and same-named policy per consumer. The shared config pins GitHub's issuer,
discovery endpoint, RS256, and an exact fleet audience.

The vault-config-operator receives two deliberately narrow `deploy-*` bootstrap
globs so convention-driven onboarding and offboarding do not require a new
owner Vault ceremony per repository. This is an explicit deviation from
ADR-0028's exact-path enumeration, tracked as TD-0014.

## Context and Problem Statement

The cluster's Kubernetes auth method proves a pod ServiceAccount identity. It
is the right mechanism for in-cluster controllers, but it cannot prove which
GitHub repository, workflow, immutable repository ID, event, or run invoked a
CI job. The ansible-runner program needs per-repository secret boundaries whose
identity grain matches the platform's existing GitHub/Sigstore supply-chain
identity.

GitHub Actions emits an issuer-signed OIDC token containing those claims. Vault
can validate that token at every login without storing a GitHub credential.
The shared GitHub discovery document rotates signing keys, so Vault needs a
single exact-host egress path to `token.actions.githubusercontent.com`.

Enabling an auth mount is `sys/auth` lifecycle work and requires Vault `sudo`.
That privilege is intentionally absent from the GitOps reconciler, preserving
the bootstrap boundary in ADR-0028.

## Decision

### Authentication methods coexist

Keep `auth/kubernetes` for in-cluster callers. Add owner-enabled
`auth/jwt-github` only for GitHub Actions CI consumers. The
vault-config-operator configures the existing mount through one managed
`JWTOIDCAuthEngineConfig`; it does not enable or disable the mount.

The config is:

- path `jwt-github`;
- issuer and discovery URL
  `https://token.actions.githubusercontent.com`;
- supported algorithm exactly `RS256`;
- no static JWKS URL, validation key, or default role;
- protected by an exact-host DNS + TCP/443 CiliumNetworkPolicy;
- covered by generation-aware Flux health checks for both the config and role
  CR kinds.

### Consumer identity is repository-scoped

Each later CI consumer gets a managed `JWTOIDCAuthEngineRole` and `Policy` with
the same `deploy-<repo>` name. The role binds:

- the exact audience `vault.deploy-vault.svc.cluster.local`;
- `userClaim: repository_id`;
- scalar `workflow_ref`, `repository_id`, and `repository_owner_id` claims;
- exact events `[push, workflow_dispatch]`;
- mappings for `run_id`, `run_attempt`, `actor`, `sha`, and `workflow_ref`;
- batch tokens with no default policy, no period, a positive TTL no greater
  than 900 seconds, and no max-TTL field greater than that TTL;
- exactly its one same-named policy.

CI guards fail closed on every field and on role→policy→config reference
integrity before a role can enter the prune-armed managed inventory.

### One owner ceremony, one combined grant set

The owner enables the mount and re-seeds the reviewed bootstrap HCL before the
draft implementation PR may merge. The grant delta is exactly:

```hcl
path "auth/jwt-github/config" {
  capabilities = ["create", "read", "update"]
}
path "auth/jwt-github/role/deploy-*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "sys/policies/acl/deploy-*" {
  capabilities = ["create", "read", "update", "delete"]
}
```

The config path has no delete. The role and policy globs include delete solely
for offboarding. There is no `list`, `sudo`, broader auth/policy wildcard, or
GitHub-wide network grant.

### Deliberate deviation from exact-path enumeration

ADR-0028's default is one exact bootstrap path per managed object. Per-consumer
exact grants would require an owner Vault re-seed for every repository and
defeat convention-driven automatic onboarding. The accepted precedent is the
repository's use of tightly bounded final-segment globs where the resource
namespace itself is the trust boundary. Here both globs are confined to the
`jwt-github` mount or the `deploy-*` policy-name prefix, guarded for exact
spelling/capabilities, and logged as TD-0014 rather than presented as exact
enumeration.

## Consequences

- GitHub Actions identity and Kubernetes workload identity remain separate and
  auditable instead of overloading a ServiceAccount boundary.
- A failed config or role reconcile cannot present healthy: current-generation
  `ReconcileSuccessful=True` is mandatory.
- A compromised vault-config-operator can create, rewrite, or delete any
  `deploy-*` JWT role or ACL policy, not only currently onboarded names. This is
  the bounded but real expansion recorded in TD-0014.
- GitHub discovery availability becomes an authentication dependency. The
  dedicated exact-host CNP exposes only the necessary DNS and TLS path.
- Batch tokens are irrevocable within their TTL. A stolen in-cluster bearer
  token remains replayable until expiry.
- Re-running an old GitHub run may re-authenticate against a still-present role;
  mapped run identity makes the event auditable but does not prevent it.
- This foundation alone authenticates nobody. No job can log in until a later
  consumer PR adds a role and policy and the owner merges it.
- The v0.8.49 config CR is non-deletable. Rollback must retire roles, prune the
  CR, owner-disable the mount, then remove egress and bootstrap grants.

## Alternatives Considered

- **Use Kubernetes auth for GitHub jobs.** Rejected: it proves only the runner
  pod's ServiceAccount, collapsing every repository sharing that compute onto
  one identity.
- **Pin GitHub signing keys in git.** Rejected: key rotation becomes a silent
  outage and creates an emergency update path.
- **Use per-consumer exact bootstrap grants.** Rejected for the ratified
  automatic-onboarding model: it adds an owner Vault ceremony to every repo.
  It remains the preferred TD-0014 closure if automatic onboarding is retired.
- **Let the operator enable the auth mount.** Rejected: it requires `sys/auth`
  `sudo` and materially expands the reconciler's authentication-plane power.

## References

- [Owner ceremony runbook](../../runbooks/enable-jwt-github-auth-mount.md)
- [ADR-0028](0028-vault-config-operator-bootstrap-identity.md)
- [TD-0014](../../tech-debt.md#td-0014--jwt-github-bootstrap-uses-deploy--wildcard-grants)
- `scripts/check-vault-jwt-github-invariants.py`
- `scripts/check-vault-config-operator-bootstrap-invariants.py`
- `scripts/check-vault-config-reference-safety.py`
