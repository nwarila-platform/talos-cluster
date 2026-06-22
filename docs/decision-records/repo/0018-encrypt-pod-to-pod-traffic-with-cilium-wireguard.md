# ADR-0018: Encrypt pod-to-pod traffic with Cilium WireGuard

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-21                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | [ADR-0009](0009-stig-cis-compliance-baseline.md), [ADR-0008](0008-gitops-via-flux.md), Cilium dataplane choice |
| Informed       | future platform operators               |
| Reversibility  | High                                    |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Enable Cilium transparent pod-to-pod encryption cluster-wide with WireGuard in
`addons/cilium/values.yaml`: `encryption.enabled: true`,
`encryption.type: wireguard`, `encryption.nodeEncryption: false`, and
`MTU: 1380`. The change is live from Step 145 / PR #201 and required both
`helm upgrade` and an explicit `kubectl rollout restart ds/cilium` because
`enable-wireguard` and `mtu` are Cilium agent-startup-only flags.

This protects pod-to-pod traffic from node-underlay sniffing or man-in-the-middle
tampering while deliberately leaving host/node-plane traffic cleartext and
firewalled.

## Context and Problem Statement

Before this decision, pod-to-pod traffic crossed the node underlay as cleartext
inside the unencrypted VXLAN overlay on UDP 8472. An adversary with access to
the node network or underlay, such as a compromised or rogue device on the node
subnet, a switch-level tap, or a node-to-node man-in-the-middle, could read or
tamper with inter-pod traffic in transit.

That exposure included secret-bearing flows such as Vault client traffic, tenant
data, and control-plane-adjacent traffic. Host firewalling and default-deny
NetworkPolicy with Cilium constrain who may connect, but they do not protect
confidentiality or integrity for packets already authorized onto the wire.

[ADR-0009](0009-stig-cis-compliance-baseline.md) accepts a STIG/CIS-oriented
security baseline that includes encryption in transit. The cluster needed a
transparent dataplane encryption layer that closes the node-underlay sniff/MITM
threat without requiring every workload to adopt its own transport security at
the same time.

## Decision

Enable Cilium transparent pod-to-pod encryption cluster-wide using WireGuard.
The accepted values in `addons/cilium/values.yaml` are:

```yaml
encryption:
  enabled: true
  type: wireguard
  nodeEncryption: false
MTU: 1380
```

The change was applied with `helm upgrade` plus the required
`kubectl rollout restart ds/cilium`. Updating the `cilium-config` ConfigMap
alone is insufficient for this class of change because `enable-wireguard` and
`mtu` are read by the Cilium agent at startup. Future Cilium startup-flag changes
must include a DaemonSet rollout in both the apply and rollback paths.

WireGuard is chosen over Cilium IPsec because Cilium auto-manages per-node
WireGuard keys, Talos already has WireGuard in-kernel (`CONFIG_WIREGUARD=y`),
and WireGuard uses modern fixed cryptography with fewer operational moving parts
than IPsec. IPsec would add PSK or certificate lifecycle management and has
carried more Cilium operational complexity.

`nodeEncryption: false` is deliberate. Host/node-plane traffic remains cleartext
and constrained to the node subnet by the Talos host firewall default-block
posture and per-port allowlist. The sensitive tenant and secret-bearing traffic
is pod-to-pod and is encrypted by this decision. `nodeEncryption: true` is still
beta in Cilium and has an open MTU defect, so it is deferred.

`MTU: 1380` is deliberate because WireGuard wraps the VXLAN-encapsulated payload.
On a standard 1500-byte underlay, the budget is 1500 − 50 bytes for VXLAN − 60
bytes for WireGuard = 1390 bytes. The configured 1380 MTU leaves margin so
encrypted frames do not exceed the underlay MTU and silently blackhole. Newly
scheduled pods receive MTU 1380; existing 1500-MTU pods rely on Cilium TCP MSS
clamping and were not bounced.

UDP 51871 for `cilium_wg0` was already opened by the Step 140 Talos host
firewall rule `ingress-cilium-wireguard`, restricted to the node and operator
subnets.

## Consequences

### Positive

- Pod-to-pod traffic now has transparent confidentiality, integrity, and
  authenticity at the dataplane layer.
- The node-underlay sniffing and node-to-node MITM threat for pod traffic is
  closed.
- The implementation advances the [ADR-0009](0009-stig-cis-compliance-baseline.md)
  encryption-in-transit posture without requiring application-by-application
  mTLS migration.
- Cilium manages per-node WireGuard keys, avoiding a separate IKE, PSK, or
  certificate lifecycle for dataplane encryption.

### Negative

- WireGuard adds modest per-node CPU and throughput overhead.
- Pod MTU is reduced to 1380 for new pods, with existing pods depending on
  Cilium TCP MSS clamping until they are naturally rescheduled.
- Cilium startup-flag changes are easy to misapply: `helm upgrade` updates
  configuration, but the behavior is a silent no-op until `ds/cilium` is
  restarted.

### Neutral

- Host/node-plane traffic remains cleartext by design and is accepted as
  firewalled node-subnet traffic.
- The decision is highly reversible by setting the Helm value back and running
`kubectl rollout restart ds/cilium`.
- Application-layer mTLS remains useful for service identity and end-to-end
  workload trust, but it is orthogonal to this transparent dataplane control.

## Alternatives Considered

1. Use Cilium IPsec transparent encryption.

   Rejected. IPsec would provide dataplane encryption, but it adds key or
   certificate lifecycle complexity, heavier operational handling, and more
   moving parts than WireGuard for this Talos cluster.

2. Enable Cilium `nodeEncryption: true`.

   Deferred. It would also encrypt host/node-plane traffic, but that traffic is
   already constrained by the Talos host firewall and node subnet boundary.
   Cilium node encryption is beta and has an open MTU defect, so enabling it now
   would add risk outside the pod-to-pod threat being closed.

3. Keep relying on host firewalling and NetworkPolicy alone.

   Rejected. Those controls constrain who can connect, but they do not provide
   on-wire confidentiality or integrity after traffic is allowed. That would
   leave the node-underlay sniff/MITM threat open and weaker than the
   ADR-0009 encryption-in-transit posture.

4. Require application-layer mTLS only.

   Rejected as the sole answer. Application mTLS is useful but heavier,
   workload-specific, and does not transparently cover all pod-to-pod traffic.
   It remains complementary rather than a replacement for dataplane encryption.

## Verification

Verification was performed during the live Step 145 implementation:

1. All six Cilium agents reported `Encryption: Wireguard`.
2. `cilium_wg0` was present with a full five-peer mesh on UDP 51871.
3. A freshly scheduled pod received MTU 1380.
4. Cross-node `iperf3` between pods on different workers ran at approximately
   840 Mbit/s with 0 retransmits, proving the encrypted large-frame path without
   MTU blackholing.
5. UDP 51871 was confirmed on the wire.
6. Vault HA, etcd with three members, herowars, all six nodes, and Cilium
   cluster-health with 6/6 reachable nodes stayed healthy under encryption.

## Related

- [ADR-0008](0008-gitops-via-flux.md) - records Flux as the cluster-level
  reconciliation model that now owns Cilium configuration.
- [ADR-0009](0009-stig-cis-compliance-baseline.md) - records the STIG/CIS
  security baseline and encryption-in-transit posture this decision advances.
- [`addons/cilium/values.yaml`](../../../addons/cilium/values.yaml) - records
  the accepted live Cilium WireGuard and MTU values.
- [PR #201](https://github.com/nwarila-platform/talos-cluster/pull/201) /
  commit `8cad9f5` - implemented the live Cilium WireGuard encryption rollout.
