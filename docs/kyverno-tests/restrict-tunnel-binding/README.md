# Offline Validation — Restrict Tunnel Binding

This suite evaluates
`clusters/talos-cluster/apps/kyverno/policies/restrict-tunnel-binding.yaml`
with the Kyverno CLI version used by the cluster.

## Run

```bash
bash docs/kyverno-tests/restrict-tunnel-binding/validate.sh
```

The runner supports Linux x86_64 and requires `curl`, `python3` with PyYAML,
`sha256sum`, and `tar`. It downloads Kyverno CLI v1.18.2 from the upstream
release and verifies the archive against the pinned release SHA-256 checksum
before execution.

The values file supplies the labelled Namespace objects needed by
`namespaceObject` and `namespaceSelector`. Every fixture is checked for its
exact policy result and message. The suite covers both registered orgs,
cross-org attempts, absent and near-match class values, absent and unregistered
org labels, deprecated annotation variants, the forbidden default-class
annotation, and unaffected non-tenant namespaces. The unregistered fixture
fails both later branches and proves message precedence `a` over `c` and `b`;
the annotation-only fixture proves `c` over `b`.

Kyverno CLI assigns a synthetic `default` namespace when it evaluates the
cluster-scoped IngressClass fixture and applies the policy's namespace selector
to it. The values file labels that synthetic Namespace as a tenant so the CLI
evaluates the default-class validation. In live Kubernetes admission,
`namespaceSelector` does not skip cluster-scoped resources.

## Coverage Boundary

This offline suite proves CREATE-object evaluation only. Kyverno CLI v1.18.2's
ValidatingPolicy processor hardcodes its synthetic admission request operation
to `Create`. It cannot prove UPDATE or `ingresses/status` behavior. Those paths,
including annotation mutation through the status subresource, are proven only
by the post-merge live probe in exit gate 6.
