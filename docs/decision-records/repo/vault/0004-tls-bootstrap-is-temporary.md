# ADR-0004: Treat `tls_disable` as a temporary bootstrap state only

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Closed                                  |
| Date           | 2026-06-01                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Medium                                  |
| Review-by      | 2026-09-01                              |

## TL;DR

The Vault listener may run with `tls_disable = 1` **only** as a documented,
time-boxed bootstrap state. The steady state is TLS-on; Vault is not exposed
beyond the namespace until TLS is enabled.

## Context and Problem Statement

A secrets manager serving its API in plaintext means unseal keys, tokens, and
secrets traverse the pod network unencrypted. The cluster currently has **no
cert-manager** and no PKI/issuer in the apps set. We need TLS to be a
deliberate, tracked decision rather than an accidental permanent state.

## Decision Drivers

- Plaintext is unacceptable for a secrets manager in steady state.
- cert-manager / an issuer is not yet installed (a prerequisite to add).
- The bootstrap config and the TLS-on config are both pre-authored so the flip
  is a config swap, not a redesign.

## Considered Options

1. **Bootstrap plaintext → flip to listener TLS** (cert-manager issued certs).
2. Terminate TLS at the Cilium Gateway, plaintext to Vault (rejected: leaves the
   in-cluster hop and Raft peer traffic in cleartext for a secrets manager).
3. Ship TLS from day one (blocked until cert-manager exists).

## Decision Outcome

**Chosen: Option 1.** Bootstrap with `tls_disable = 1` and HTTP probes **only
long enough to initialize/unseal and validate**. Before any exposure, install
cert-manager, issue a server cert + CA, mount them read-only at `/vault/tls`,
switch `vault.hcl` to the TLS-on variant (`tls_min_version = "tls13"`,
`tls_client_ca_file` for Raft peer mTLS), and flip **all** probes to
`scheme: HTTPS`. `cluster_addr` is `https://` in both states (the Raft cluster
port is always TLS internally).

## Confirmation

Post-flip, `vault status` over HTTPS succeeds; kubelet HTTP**S** probes pass
(kubelet does not verify the cert, so a bootstrap CA is acceptable for probes,
but the API `listener` must not require client certs on 8200). Raft `retry_join`
succeeds with the chosen CA.

Closing note, 2026-06-12: the TLS listener flip landed in implementation. Vault
now serves on HTTPS with a `pki-int-tcn`-issued serving certificate delivered
through the SOPS-managed `vault-serving-cert` Secret; startup, readiness, and
liveness probes use HTTPS; and Raft retry-join uses HTTPS with the mounted CA.
The implemented PKI architecture is recorded in
[ADR-0013](0013-adopt-offline-root-vault-pki-for-internal-tls.md).

## Consequences

### Positive
- A clear, auditable path from insecure bootstrap to TLS steady state.

### Negative
- Adds a cert-manager dependency and a cert-rotation lifecycle to own.
- A window of plaintext exists during bootstrap (mitigated: internal-only, short).

## Related ADRs

- [ADR-0005](0005-internal-only-before-gateway-exposure.md) — no exposure pre-TLS.
- [ADR-0013](0013-adopt-offline-root-vault-pki-for-internal-tls.md) — offline-root
  Vault PKI and the implemented listener TLS foundation.
