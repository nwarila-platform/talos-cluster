# ADR-0025: Publish the Public Repository with Full Topology

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-07-10                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | current public repository state, `cluster/config.env`, `.gitignore`, `.sops.yaml`, ADR-0003, ADR-0010, ADR-0012, ADR-0018, ADR-0024 |
| Informed       | future platform operators and reviewers |
| Reversibility  | Medium - making a repo private is easy but the history is already public |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Keep `nwarila-platform/talos-cluster` public with its real homelab topology
visible. This is a deliberate portfolio decision, not an accidental leak and
not an apology for weak controls.

The accepted disclosure is reconnaissance: RFC1918 addresses, subnet and VLAN
layout, node hostnames, storage targets, and exact version pins. The repository
must not rely on hiding those facts. Its security model must hold when an
attacker can read the topology: no plaintext secrets in git, SOPS-encrypted
Secret payloads, deny-all `.gitignore`, signed commit governance, CI and
Kyverno boundary guards, default-deny network intent, signed image admission,
and KMS-sealed Vault.

This trade is acceptable for this portfolio homelab because the disclosed
topology is not internet-routable, the Kubernetes and Talos control planes are
not intentionally exposed to the public internet, there are no production
tenants or third-party user data at risk, and the repository does not disclose
private keys, kubeconfigs, talosconfigs, recovery material, unencrypted
Kubernetes Secret values, or routable cluster control-plane endpoints.

## Context and Problem Statement

This repository is the source of truth for `TDNHQ-TALCL01`, a real running
Talos Kubernetes homelab platform. It is also intentionally public as a
portfolio artifact. The public content includes internal topology:

- RFC1918 control-plane and node addresses in `cluster/config.env`;
- subnet, gateway, VIP, and endpoint layout;
- node inventory and hostnames;
- storage and backup target structure;
- exact Talos, Kubernetes, Cilium, Longhorn, Flux, Kyverno, and application
  version pins; and
- GitOps, recovery, network-policy, Vault, and tenant boundary design.

In a normal production environment, publishing that information is bad
practice. Internal topology helps reconnaissance. It lets an attacker skip
discovery steps, select likely exploit paths faster, craft more plausible
phishing or change-proposal pretexts, and plan lateral movement if they already
obtain network access or a credential. Version disclosure can also shorten the
time between a known vulnerability and a targeted exploit attempt.

For a production system serving real users or tenants, the value side of this
trade would collapse while the risk side would rise. There is no portfolio
benefit that belongs to users, the blast radius includes other people's data,
and least-disclosure, contractual, and compliance expectations become stronger
than this homelab portfolio rationale. This ADR is therefore not a general
permission to publish production topology.

That general rule does not settle this repository's decision. This repository
exists in part to prove infrastructure judgment through real, inspectable
architecture. A scrubbed, fake, or private repository would not demonstrate the
same thing. The decision to publish topology therefore needs an explicit threat
model and risk acceptance.

The important distinction is between topology as reconnaissance and secrets as
authority. Topology tells an attacker where things would be if they were already
in a position to reach them. It does not provide a route through NAT/firewall
boundaries, a Kubernetes credential, a Talos client credential, a Vault recovery
key, a SOPS age private key, a GHCR credential, or a GitOps deploy key.

## Decision

Publish this repository publicly with full, real topology.

Security-through-obscurity is explicitly not part of the control model for this
platform. The cluster must remain defensible when the repository reader knows
the private address plan, hostnames, software versions, storage layout, and
GitOps structure. The portfolio value comes from showing the real architecture
and the real trade. The controls that matter are the ones that protect
credentials, admission, network reachability, and recovery authority.

The accepted exposure is:

1. Internal address and subnet reconnaissance.
2. Node, hostname, and role reconnaissance.
3. Storage and backup-layout reconnaissance.
4. Software-version reconnaissance.
5. Control-design reconnaissance, including GitOps, policy, Vault, and DR
   boundaries.

The exposure is accepted under these constraints:

1. RFC1918 addresses are not internet-routable.
2. The cluster sits behind NAT/firewall boundaries, and this ADR does not
   approve exposing the Kubernetes API, Talos API, etcd, Vault, Longhorn, NAS,
   or node management plane to the public internet.
3. The repository does not intentionally disclose private keys, passwords,
   tokens, kubeconfigs, talosconfigs, Talos `secrets.yaml`, Vault recovery
   material, SOPS age private keys, generated machine configs, or plaintext
   Kubernetes Secret payloads.
4. There are no production tenants or third-party user data whose safety depends
   on minimizing public architecture disclosure.
5. Version disclosure is treated as an acceleration of post-access targeting,
   not as an authorization boundary. Patch and upgrade discipline must handle
   disclosed versions as public facts.
6. A future move to real users, regulated data, public control-plane exposure,
   or commercial tenant service invalidates this risk acceptance and requires a
   new ADR.

The repository's defensive posture is therefore based on layered controls:

- `.sops.yaml` encrypts Kubernetes Secret `data` and `stringData` fields for
  YAML, YML, and JSON files before they are committed; Flux decrypts at
  reconcile time through the in-cluster `sops-age` Secret.
- `.gitignore` starts from a deny-all rule and allowlists intended source files,
  so local mirrors such as `.s3/`, generated machine configs, kubeconfigs,
  talosconfigs, and other unlisted material are not tracked by default.
- `.pre-commit-config.yaml` includes private-key detection and Gitleaks, while
  `.github/workflows/security.yaml` runs a full-history Gitleaks scan on pull
  requests and on a weekly schedule.
- Repository governance requires signed commits for mainline changes. This is a
  provenance and tamper-resistance control, not a substitute for review or
  secret hygiene.
- `clusters/talos-cluster/apps/kyverno/policies/verify-image-signatures.yaml`
  enforces keyless cosign verification for first-party image namespaces and
  audits additional signed upstream families.
- ADR-0024 records the paired CI guard and Kyverno runtime policy that protect
  the Vault restore-validator boundary.
- Network manifests use default-deny intent for sensitive app and tenant
  namespaces, with explicit egress allowances where needed.
- ADR-0012 records the KMS-sealed Vault model, dedicated CMK, IAM Roles
  Anywhere credential delivery, and SOPS-delivered workload certificate path.
- ADR-0018 records Cilium WireGuard encryption for pod-to-pod traffic on the
  node underlay.

The residual risk is real and accepted: a person who already has LAN access, a
valid credential, or an execution foothold can use this repository as a map.
That makes post-access movement faster and secret-hygiene failures more
damaging. It does not, by itself, create a route to the cluster or confer
authority inside it. In this environment, the exposure raises the stakes on
secret-hygiene discipline and post-access defense more than it changes initial
compromise probability.

## Consequences

### Positive

- The portfolio shows real architecture rather than sanitized claims.
- Reviewers can evaluate actual Talos, Kubernetes, GitOps, Vault, storage, and
  DR decisions against concrete files.
- The repository keeps its zero-false-claims posture: public documentation,
  config, and ADRs describe the platform that actually exists.
- The control model is stronger because topology is treated as non-secret and
  actual secrets and boundaries are the protected assets.
- The risk decision is reviewable, auditable, and reusable as evidence of
  threat-model literacy.

### Negative

- The topology is permanently present in git history even if the repository is
  later made private.
- A future secret-hygiene mistake has higher impact because an attacker can
  combine the leaked secret with a detailed map.
- Version disclosure can reduce an attacker's research time after a relevant
  CVE or after network access is obtained.
- Hostnames, storage layout, and operational terminology can make targeted
  social-engineering or malicious-change attempts more credible.
- The repository must preserve an absolute "no real secrets, ever" discipline;
  any exception is a security incident, not a documentation issue.

### Neutral

- This ADR does not change cluster behavior, firewall exposure, GitHub
  visibility, or GitOps reconciliation.
- Making the repository private later may reduce casual discovery, but it cannot
  erase already-public history or forks.
- RFC1918 address disclosure is not treated as a credential, authorization
  mechanism, or compensating control.
- Public topology remains acceptable only while the assumptions below remain
  true.

## Alternatives Considered

1. Make the repository private.

   Rejected. This removes the primary portfolio value: external reviewers would
   no longer be able to inspect the real architecture, controls, and tradeoffs.
   It also does not fully reverse the current state because the topology is
   already present in public git history.

2. Keep the repository public but scrub or fake topology.

   Rejected. Scrubbing or fabricating addresses, hostnames, versions, storage
   targets, or control relationships would violate the repository's
   zero-false-claims principle. It would also break the reproducibility and
   review value of the documentation because reviewers could not distinguish
   real architecture from presentation.

3. Keep the repository public with full topology and record this ADR.

   Chosen. This keeps the portfolio honest and inspectable while making the
   accepted reconnaissance risk explicit. The security obligation becomes
   precise: never commit authority-bearing material, keep public topology
   non-authoritative, and maintain controls that remain valid when the map is
   known.

## Assumptions

1. The Kubernetes API, Talos API, etcd, Vault, Longhorn, NAS, and node
   management surfaces are not intentionally reachable from the public internet.
2. The cluster remains a portfolio homelab without production tenants,
   third-party user data, or regulated customer workloads.
3. The committed repository contains no unencrypted secrets, private keys,
   kubeconfigs, talosconfigs, Talos `secrets.yaml`, SOPS age private key,
   generated machine configs, or live recovery material.
4. SOPS, deny-all `.gitignore`, Gitleaks, pre-commit checks, CI validation, and
   code review continue to be treated as mandatory secret-hygiene controls.
5. Publishing version pins does not reduce the obligation to patch, upgrade, and
   retire vulnerable components promptly.
6. If the platform begins serving real users, exposes a public control plane, or
   stores third-party data, this ADR must be superseded before continuing the
   same publication posture.

## Out of Scope

- Publishing or approving any secret, private key, token, kubeconfig,
  talosconfig, Talos `secrets.yaml`, SOPS age private key, generated machine
  config, or Vault recovery material.
- Opening any new public ingress path or changing firewall, NAT, Talos host
  firewall, Kubernetes admission, or NetworkPolicy behavior.
- Deciding physical security, home-network ISP exposure, or residential address
  disclosure policy.
- Defining a general rule for production systems that serve real users or hold
  regulated third-party data.
- Replacing patch management, vulnerability response, code review, or secret
  scanning with this ADR.

## Related

- [`cluster/config.env`](../../../cluster/config.env) is the public inventory
  and version source of truth for this cluster.
- [`.gitignore`](../../../.gitignore) implements the deny-all tracking strategy.
- [`.sops.yaml`](../../../.sops.yaml) defines Secret payload encryption rules.
- [Security workflow](../../../.github/workflows/security.yaml) runs Gitleaks
  secret scanning.
- [Org ADR-0003](../org/0003-use-deny-all-gitignore-strategy.md) establishes
  the deny-all `.gitignore` baseline.
- [ADR-0003](0003-repo-as-cluster-source-of-truth.md) records this repository
  as the cluster source of truth.
- [ADR-0009](0009-stig-cis-compliance-baseline.md) records the STIG/CIS
  compliance baseline.
- [ADR-0010](0010-adopt-kyverno-policy-engine.md) adopts Kyverno as the policy
  engine.
- [ADR-0012](0012-vault-kms-auto-unseal-credential-delivery.md) records the
  Vault KMS auto-unseal and dedicated key model.
- [ADR-0018](0018-encrypt-pod-to-pod-traffic-with-cilium-wireguard.md) records
  Cilium WireGuard pod-to-pod encryption.
- [ADR-0024](0024-two-layer-enforcement-of-restore-validator-boundary.md)
  records the CI and Kyverno restore-validator boundary.

## Compliance Notes

This ADR is a documented, risk-accepted disclosure decision. It does not claim
that public topology is a control. It records why the disclosure is acceptable
for this environment and which controls must remain true for that acceptance to
hold.

| Framework             | Control | Relevance |
| --------------------- | ------- | --------- |
| NIST SP 800-53 Rev. 5 | RA-3    | Records the specific reconnaissance risk, affected information types, accepted threat scenarios, and conditions that would require reassessment. |
| NIST SP 800-53 Rev. 5 | PL-8    | Documents the security architecture principle that topology is non-secret and authority-bearing material, admission, network, and recovery boundaries are the protected assets. |
| NIST SP 800-53 Rev. 5 | CM-6    | Ties the public configuration baseline to explicit hardening expectations: SOPS, deny-all tracking, signed commits, CI checks, Kyverno admission, default-deny network intent, and KMS-sealed Vault. |
| NIST SP 800-53 Rev. 5 | CM-7    | Accepts public inventory disclosure only while the live platform keeps unnecessary public services and control-plane exposure out of scope. |
| NIST SP 800-53 Rev. 5 | SC-7    | Frames the acceptance around boundary protection: RFC1918 topology is public, but private control-plane and management surfaces must remain protected by NAT/firewall and cluster policy boundaries. |
