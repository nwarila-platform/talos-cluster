# ADR-0013: Adopt Offline-Root Vault PKI for Internal TLS

| Field          | Value                                                                 |
| -------------- | --------------------------------------------------------------------- |
| Status         | Accepted                                                              |
| Date           | 2026-06-12                                                            |
| Authors        | Nick Warila (@NWarila), Codex                                         |
| Decision-maker | Nick Warila (sole portfolio maintainer)                               |
| Consulted      | ADR-0004, ADR-0008, ADR-0009; HashiCorp Vault PKI and listener docs; cert-manager supported-release matrix |
| Informed       | Claude, future platform operators                                     |
| Reversibility  | Medium                                                                |
| Review-by      | 2026-09-12                                                            |

## Context and Problem Statement

Vault currently bootstraps with `tls_disable = 1` under [ADR-0004]. That was an
accepted temporary state, not the production target. The certificate
architecture decision is now broader than "get one serving certificate for
Vault": the portfolio needs a central internal CA, inventory, revocation, and a
single distribution pattern for Kubernetes workloads and standalone VMs.

The selected architecture is Candidate A refined:

1. An offline, air-gapped root CA signs per-context online intermediates.
2. Vault PKI hosts the internal online intermediate for the TCN context.
3. Vault Agent becomes the default VM and Windows/IIS delivery mechanism.
4. cert-manager with a Vault issuer becomes the Kubernetes delivery mechanism
   after the installed Kubernetes version is within cert-manager support.
5. Let's Encrypt with Cloudflare DNS-01 is used only at public browser-trusted
   edges, especially the guild context, and those certificates are later
   mirrored into Vault for inventory and uniform retrieval.

As of this ADR, the cluster is Kubernetes 1.36.0 and cert-manager 1.21 is the
first listed release planned to support Kubernetes 1.36, with a projected
release date of 2026-06-24. Therefore the Phase-1 CA foundation and Vault
listener TLS flip must not depend on cert-manager being installed first.

## Decision Drivers

1. Vault's API listener must not remain plaintext in steady state.
2. The internal CA must be recoverable without keeping the root key online.
3. The CA hierarchy must support future internal, personal, and guild contexts
   without letting one context mint names for another.
4. Vault's own serving certificate must avoid a cold-start circular dependency.
5. The implementation must respect the existing trust-root split: live cluster
   capability and secret-zero material belong in `talos-cluster`; this repo owns
   the workload's desired shape.

## Considered Options

1. **Offline root -> Vault-hosted TCN intermediate, plus public ACME only at the
   public edge.** This gives central internal issuance and inventory while
   preserving browser trust where public users require it.
2. **Let's Encrypt everywhere.** This avoids private-root distribution but loses
   internal CA control, publishes internal names or broad wildcards to CT logs,
   and makes internal renewal depend on an external public CA.
3. **Smallstep `step-ca` as the central private CA.** This is a strong ACME-first
   private CA, but Vault is already deployed, already audited, and already the
   intended inventory and secret-distribution plane.
4. **Vault Agent issues Vault's own listener certificate into an emptyDir at pod
   start.** This works for ordinary consumers, but not as the only copy of
   Vault's own serving key: after a full cold restart, Vault cannot start its
   TLS listener without a cert, and the agent cannot fetch a cert from Vault
   until Vault is already serving.

## Decision Outcome

Chosen option: **Option 1, with a durable bootstrap-breaking Secret for Vault's
own listener certificate.**

### CA hierarchy

| Layer | Decision |
| --- | --- |
| Offline root | ECDSA P-384, SHA-384, self-signed, about 20 years. The root private key is generated and stored offline only. Do not import the root private key into Vault. Do not constrain the root; keep it flexible enough to sign future constrained intermediates. |
| TCN intermediate | ECDSA P-384 key generated inside Vault by an intermediate CSR at `pki-int-tcn/`, signed offline by the root, about 10 years, path length 0. |
| Leaf certificates | Short lived. Default server leaves should be ECDSA P-256 for TLS performance and compatibility, with a 30-day default TTL and a 90-day max TTL. Renew before day 60. Use P-384 leaves only where a role explicitly requires it. |

The TCN intermediate, not the root, carries critical name constraints:

- permitted DNS: `tcn.trinitytechnicalservices.com`
- permitted DNS subtree: `.tcn.trinitytechnicalservices.com`
- permitted DNS: `cluster.local`
- permitted DNS subtree: `.cluster.local`
- permitted IP range: `10.69.112.0/24`

This lets the same intermediate issue for split-horizon
`*.tcn.trinitytechnicalservices.com` names and Kubernetes service FQDNs while
blocking issuance outside the TCN/internal context. The root remains
unconstrained so it can later sign a personal or guild intermediate without
being trapped by the first context's constraints.

Name constraints must be verified empirically before the TLS flip is treated as
complete. Go, OpenSSL, and Windows trust-chain validation are all in scope for
the estate, and the safe rule is: if any required consumer mishandles the
critical constraints, stop and fall back to role policy while deciding whether
to issue a narrower unconstrained intermediate for that consumer class.

### Vault PKI mount structure

Use one PKI mount per trust context:

| Mount | Purpose |
| --- | --- |
| `pki-int-tcn/` | Phase-1 internal TCN intermediate and issuance roles. |
| `pki-int-personal/` | Future personal context, separate intermediate. |
| `pki-int-guild/` or separate store | Future private guild context only if the owner chooses central Vault over a fully separate guild Vault. Public browser certs still use Let's Encrypt. |

Within a mount, use multiple issuers only for rotation of the same authority.
Do not mix roots and unrelated intermediates in one mount. Vault's public
issuer, CRL, and OCSP URLs must be configured before issuance so certificates
carry usable Authority Information Access and revocation pointers:

- issuing certificates:
  `https://vault.tcn.trinitytechnicalservices.com/v1/pki-int-tcn/ca`
- CRL distribution:
  `https://vault.tcn.trinitytechnicalservices.com/v1/pki-int-tcn/crl`
- OCSP:
  `https://vault.tcn.trinitytechnicalservices.com/v1/pki-int-tcn/ocsp`

Vault gives the internal inventory source of truth through PKI serial storage,
certificate listing, revocation by serial number, audit logs, CRL/OCSP, and
lease/expiration timestamps. OSS Vault does not provide Enterprise certificate
metadata as a full CLM dashboard; expiry alerts and dashboards are follow-up
monitoring work.

### Issuing roles

Use separate roles instead of one broad "server and client everything" role:

| Role | Purpose |
| --- | --- |
| `vault-server` | Exact SAN allowlist for Vault's own listener. Server auth only. 90-day max TTL. |
| `tcn-server` | Internal service TLS under the constrained DNS set. Server auth only. 30-day default TTL, 90-day max TTL. |
| `tcn-client` | mTLS client identities. Client auth only. Shorter default TTL, with URI SAN/SPIFFE naming designed before broad rollout. |
| `tcn-server-client` | Exceptional combined EKU role for workloads that truly need both server and client auth. Requires explicit review. |

Do not permit single-label Kubernetes short names on self-service roles. They
do not fit the chosen DNS name constraints and they make certificates less
portable across clients. Use FQDNs such as
`vault.deploy-vault.svc.cluster.local` and
`vault-0.vault-internal.deploy-vault.svc.cluster.local`.

IP SANs are allowed only through tightly reviewed roles. Vault role policy can
enable or disable IP SANs, but the intermediate name constraint is the control
that limits them to `10.69.112.0/24`.

### Vault listener TLS flip

The Vault listener cert is the bootstrap exception to "Vault Agent can fetch a
cert at startup." A durable Kubernetes TLS Secret must exist before the
TLS-enabled listener config is rolled out, or a full cold restart can deadlock:
Vault needs the cert to start TLS, but Vault is also the CA that would issue it.

The Phase-1 listener flip is therefore:

1. Take a pre-work recovery point: Stage-0 material, an etcd snapshot, and a
   clear rollback branch/commit.
2. Bootstrap Vault in the current plaintext internal-only state, unsealed by
   KMS plus `vault-ra-cert`.
3. Create `pki-int-tcn/`, generate the intermediate CSR in Vault, sign it
   offline, import the signed intermediate, configure URLs, and create roles.
4. Issue the first Vault listener certificate through the `vault-server` role,
   preferably by CSR so the serving private key is generated by the delivery
   workflow and not by the CA.
5. Deliver the resulting `vault-serving-cert` as a durable Secret from the
   protected side of the trust boundary. In the current architecture that means
   `talos-cluster` owns the SOPS-encrypted Secret and any single-Secret RBAC or
   renewal controller, while this repo only mounts and consumes it.
6. In a later implementation PR, mount the Secret read-only at `/vault/tls` and
   change `vault.hcl` from `tls_disable = 1` to:

   ```hcl
   listener "tcp" {
     address            = "[::]:8200"
     cluster_address    = "[::]:8201"
     tls_cert_file      = "/vault/tls/tls.crt"
     tls_key_file       = "/vault/tls/tls.key"
     tls_client_ca_file = "/vault/tls/ca.crt"
     tls_min_version    = "tls13"
   }
   ```

7. Change `retry_join` and the `VAULT_API_ADDR` / `VAULT_ADDR` values from HTTP
   to HTTPS FQDNs, and provide the CA bundle through `VAULT_CACERT`.
8. Change startup, readiness, and liveness probes to `scheme: HTTPS`.
9. Activate only through the existing reviewed deploy-vault pin-bump gate in
   `talos-cluster`. Do not let a tenant repo self-declare its own trust-root
   secret.

Required Vault listener SANs:

- `vault.tcn.trinitytechnicalservices.com`
- `vault.deploy-vault.svc`
- `vault.deploy-vault.svc.cluster.local`
- `vault-internal.deploy-vault.svc`
- `vault-internal.deploy-vault.svc.cluster.local`
- `vault-0.vault-internal.deploy-vault.svc`
- `vault-1.vault-internal.deploy-vault.svc`
- `vault-2.vault-internal.deploy-vault.svc`
- `vault-0.vault-internal.deploy-vault.svc.cluster.local`
- `vault-1.vault-internal.deploy-vault.svc.cluster.local`
- `vault-2.vault-internal.deploy-vault.svc.cluster.local`

Do not include short SANs such as `vault`, `vault-internal`, or
`*.vault-internal`. Use FQDNs instead. Add IP SAN `10.69.112.62` only if a
client truly connects to the VIP by IP rather than by DNS.

Vault's TCP listener documentation marks `tls_cert_file` as reloadable on
SIGHUP, so a future renewer may update the Secret and signal Vault. The safer
first implementation is a controlled one-pod-at-a-time rolling restart after a
Secret update, because it exercises the same cold-start path the system must be
able to survive. A SIGHUP reloader can be added after the restart path is
proven.

Rollback is a pin rollback to the last HTTP listener commit plus the matching
HTTP probes and `retry_join` URLs. Do not delete the PKI mount or the root
material during rollback; they are not the unsafe part.

### Bootstrap and circular-dependency analysis

There is no circular dependency between Vault unseal and Vault listener TLS:

- `vault-ra-cert` remains issued by the offline CA path used for AWS IAM Roles
  Anywhere. It is not issued by Vault PKI because Vault needs it before Vault is
  available.
- Vault still starts first in the current internal plaintext bootstrap state,
  unseals through AWS KMS, and only then hosts `pki-int-tcn/`.
- The Vault listener serving cert is a different certificate with different
  purpose and policy. It is issued after Vault is initialized.
- A durable `vault-serving-cert` Secret breaks the cold-start loop for the
  TLS-enabled steady state.

### Phase roadmap

1. **Phase 1: CA foundation and Vault listener TLS.** Offline root ceremony,
   Vault-hosted TCN intermediate, roles, first durable Vault serving cert, TLS
   listener flip, rollback plan, and expiry alerting.
2. **Phase 2: VM delivery.** Vault Agent on Linux and Windows/IIS, including
   Windows certificate-store import and IIS binding reload.
3. **Phase 3: Kubernetes delivery.** cert-manager Vault issuer and trust-manager
   after Kubernetes 1.36 is supported by the cert-manager release in use.
4. **Phase 4: Public edge.** Let's Encrypt plus Cloudflare DNS-01 for browser
   trust, with isolated Cloudflare token, ACME account, issuer, and namespace
   for the guild.
5. **Phase 5: Unified inventory.** Mirror public-edge certificates into Vault
   KV so consumers still pull from Vault paths even when issuance was public
   ACME.
6. **Phase 6: Optional abstraction.** A managed-certificate declaration layer
   that chooses Vault PKI or Let's Encrypt by policy.

## Consequences

### Positive

- Removes the design blocker for closing ADR-0004's plaintext listener.
- Keeps the root key offline and limits the online intermediate to one context.
- Gives the internal estate one CA/inventory/revocation plane.
- Avoids depending on cert-manager before Kubernetes 1.36 support is available.
- Explicitly handles Vault's own cold-start certificate problem instead of
  hiding it behind Vault Agent.

### Negative

- A private internal root must be distributed to controlled clients.
- The first Vault serving cert needs a protected durable delivery path outside
  this tenant repo.
- OSS Vault still needs external monitoring for "cert expires soon" dashboards.
- Name constraints are powerful but must be tested against every required client
  stack before broad rollout.

### Neutral

- Let's Encrypt remains required for public browser trust. The central store can
  be Vault, but the single issuer ideal is impossible across private internal
  mTLS and public browser endpoints.

## Confirmation

The 2026-06-12 implementation proved the core criteria:

1. The root private key never entered a Git working tree; it was generated
   offline. Only the public root certificate is committed as a trust-anchor
   reference.
2. The Vault intermediate CSR was generated inside Vault and signed offline.
3. The TCN intermediate carries critical name constraints for the intended TCN,
   `cluster.local`, and `10.69.112.0/24` scopes.
4. The chain verifies with OpenSSL: `pki-int-tcn.crt: OK`.
5. Vault serves HTTPS with a `pki-int-tcn`-issued listener certificate delivered
   through the durable SOPS `vault-serving-cert` Secret.
6. Startup, readiness, and liveness probes pass over HTTPS.
7. Raft re-formed over HTTPS; the controlled rolling restart proved the
   cold-start path using the durable serving-cert Secret.

Non-secret ceremony evidence:

- Root certificate SHA-256 fingerprint:
  `7A:B0:B2:82:FC:AF:00:E5:18:72:1F:1C:F0:04:77:78:51:FD:BA:B5:85:67:F9:BA:87:7E:48:1F:5D:1D:6C:38`
- Intermediate issuer ID: `335bb0fb-1567-e9c3-e44d-f4fcc4887bf6`
- Initial PKI roles: `vault-server`, `tcn-server`, `tcn-client`

Remaining confirmation item: empirical Go, OpenSSL, and Windows client
validation for constrained chains and out-of-scope-name rejection.

## Honest Gaps and Risks

- The exact renewal controller for Vault's own serving Secret is not designed
  here. The first implementation may be operator-gated, but production steady
  state needs automated reissue, Secret update, alerting, and either SIGHUP or
  rolling restart.
- Windows/IIS delivery is Phase 2. This ADR reserves the pattern but does not
  prove the import/binding reload script.
- cert-manager, trust-manager, Gateway API certificate binding, and Cilium
  `cilium-secrets` namespace details are Phase 3 and must be validated against
  the release actually supporting Kubernetes 1.36.
- Guild isolation remains an owner decision: central Vault with strict mounts
  and policies versus a fully separate guild Vault/store.

## Related ADRs

- [ADR-0004](0004-tls-bootstrap-is-temporary.md) - the plaintext listener state
  this design is intended to close.
- [ADR-0008](0008-adopt-kms-auto-unseal.md) - KMS auto-unseal remains the
  bootstrap path.
- [ADR-0009](0009-recovery-escrow-and-bootstrap-ceremony.md) - root-key escrow
  discipline follows the same "most sensitive material" handling model.

## References

- HashiCorp Vault PKI secrets engine:
  <https://developer.hashicorp.com/vault/docs/secrets/pki>
- HashiCorp Vault PKI considerations:
  <https://developer.hashicorp.com/vault/docs/secrets/pki/considerations>
- HashiCorp Vault PKI API:
  <https://developer.hashicorp.com/vault/api-docs/secret/pki>
- HashiCorp Vault TCP listener configuration:
  <https://developer.hashicorp.com/vault/docs/configuration/listener/tcp>
- cert-manager supported releases:
  <https://cert-manager.io/docs/releases/>
