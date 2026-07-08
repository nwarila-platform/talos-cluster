# Vault Restore Validator Boundary

This directory defines the first inert boundary slice for the automated Vault
restore validator proposed by ADR-0020.

It is intentionally not referenced from
`clusters/talos-cluster/apps/kustomization.yaml` yet. While ADR-0020 remains
`Proposed`, this path is rendered only by CI guard checks and is not reconciled
by Flux.

Current scope:

- reserve the future `dr-validate` namespace boundary;
- define the future validator identities with no standing token automount;
- bind those identities only to an empty namespace-local role;
- default-deny all pod ingress and egress in the namespace;
- prove with CI that this slice has no live Vault reachability, no live Vault
  resource names, no cluster-scoped RBAC, no runnable workload, and no
  generate-root recovery config.

Out of scope for this slice:

- recovery shares;
- generated root tokens;
- Vault snapshot restore;
- Longhorn restore;
- Jobs, CronJobs, Deployments, StatefulSets, or Pods;
- permissions to live `deploy-vault` resources.
