# Offline Validation — Restrict Tunnel Hostnames

This suite evaluates the hwg hostname and TCP 8080 backend contract with the
same Kyverno CLI version as the cluster.

```bash
bash docs/kyverno-tests/restrict-tunnel-hostnames/validate.sh
```

The core MVP matrix covers an admitted numeric-8080 Service backend; out-of-zone,
apex, canary, wildcard, catch-all, TLS, and provider-annotation denials; named,
resource, non-8080, and missing-path backend denials; and pass-through objects
whose cft2 org/class/legacy preconditions already fail. It is intentionally not
the exhaustive negative matrix deferred to PF-5.
