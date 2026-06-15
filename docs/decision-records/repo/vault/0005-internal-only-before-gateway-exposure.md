# ADR-0005: Deploy internal-only before any Gateway exposure

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-01                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | 2026-09-01                              |

## TL;DR

The first deployment is **internal-only**: a `ClusterIP` Service, no
`HTTPRoute`, and no allow-gateway-ingress NetworkPolicy. Expose Vault via the
Cilium Gateway **only after** TLS ([ADR-0004]) and auth are correct.

## Context and Problem Statement

The cluster uses Cilium Gateway API for ingress and a default-deny NetworkPolicy
model per tenant. Exposing a sealed/misconfigured Vault, or one without TLS and
auth, is a needless risk. We want a safe default that requires a deliberate
later step to expose.

## Decision Drivers

- Default-deny tenant model makes internal-only the natural safe default.
- Exposure should follow, not precede, TLS + auth correctness.

## Considered Options

1. **Internal-only first; Gateway exposure as a gated follow-up.**
2. Expose via Gateway immediately.

## Decision Outcome

**Chosen: Option 1.** The namespace's onboarding NetworkPolicies are default-deny
+ allow-DNS; this repo adds only the egress (kube-apiserver) and intra-namespace
(Raft 8201 / API 8200) policies Vault needs. The `allow-gateway-ingress`
NetworkPolicy and any `Gateway`/`HTTPRoute` are intentionally **omitted** until a
later, explicit change once [ADR-0004] (TLS) is satisfied.

## Confirmation

From outside the namespace, Vault is unreachable; from inside, peers form a Raft
quorum and the API Service resolves. No `HTTPRoute` exists in the manifests.

## Consequences

### Positive
- Minimal exposure during bring-up; reversible, low-risk default.

### Negative
- External clients cannot reach Vault until the exposure follow-up lands.

## Related ADRs

- [ADR-0004](0004-tls-bootstrap-is-temporary.md) — exposure is gated on TLS.
