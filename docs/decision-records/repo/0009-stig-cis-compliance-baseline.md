# ADR-0009: STIG / CIS Benchmark as the Compliance Baseline

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-05-26                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | Low                                     |
| Review-by      | N/A (Accepted)                          |

## TL;DR

Every component this repository configures — Talos machine configs, Kubernetes machinery, Helm-managed addons, in-cluster workloads — is configured to be as compliant as possible with the **DISA Kubernetes Security Technical Implementation Guide (STIG)** as the primary framework, and the **CIS Kubernetes Benchmark v1.10.x** as the secondary framework. Where the two conflict on a specific item, **STIG takes precedence** because it is the stricter superset and the policy framing ("greatest extent possible") is compliance-first. Where Talos's immutable architecture makes an item structurally non-applicable (no shell, no `/etc/passwd`, no SSH, no package manager), the deviation is documented as `N/A — Talos architecture` rather than `failed`. Verification is via [`kubescape`](https://kubescape.io/) running as a scheduled GitHub Actions workflow that uploads SARIF to GitHub Code Scanning, supplemented by per-PR manual review of STIG items the scanner doesn't cover (workload-specific STIGs, NGINX hardening, etc.). Accepted deviations from the baseline are recorded explicitly in this ADR and updated as the cluster evolves.

## Context and Problem Statement

Until this ADR, the cluster's compliance posture was implicit: individual hardening decisions (PodSecurity baseline enforce, kubelet rotate-server-certificates, Talos RBAC, audit logging) were made in their own commits without an overall framework declaring what "compliant enough" meant. Subsequent decisions to *defer* hardening (ADR-0006 commit 2afcd91 deferring CP metrics bind-addresses; commit 6724c09 keeping PodSecurity exemptions empty; commit 9974cb7 omitting explicit certSANs) were each defensible individually but had no compliance-baseline reference to be measured against.

The cluster also has no automated compliance scanning. `scripts/drift-check.sh` ([ADR-0003 §3](0003-repo-as-cluster-source-of-truth.md)) verifies that the repo matches the live cluster; it does not verify either side against any benchmark. A `kubectl get nodes` showing all `Ready` says nothing about whether `--anonymous-auth` is off on kube-apiserver, whether the audit log retention meets STIG's 90-day minimum, or whether ingress-nginx is running with TLSv1.0 enabled.

Operator-stated requirement (2026-05-26): *"to the greatest extent possible, we must configure EVERYTHING to be as STIG/CIS Benchmark compliant as possible."* This ADR is the formal landing of that requirement as the configuration-baseline policy for the repository.

## Decision Drivers

1. **Operator policy.** "Greatest extent possible" compliance with STIG and CIS is now the configuration-baseline target. Every future change must consider compliance impact.
2. **Talos architectural reality.** Talos is immutable and API-managed. Many CIS Distribution Independent Linux items don't apply because there is no shell to harden, no `/etc/passwd` to permission-check, no SSH to disable. The baseline must distinguish *non-compliant* from *not-applicable* to avoid false-negative noise.
3. **Continuous verification, not point-in-time.** A one-shot kube-bench scan that lives in someone's terminal history doesn't help. Compliance verification must run on a schedule, surface regressions, and live in the repo as artifacts.
4. **Don't break existing workloads to chase a checkbox.** Several CIS items would require breaking changes (e.g., enabling `--anonymous-auth=false` could break a poorly-configured legacy client). Deviations are accepted only when explicitly documented + justified, never silently.
5. **Aspirational, not contractual.** This cluster is not under a DoD contract. STIG/CIS compliance is the *aspirational ceiling*, not a hard requirement that overrides operational reality. Where they're impractical, document and move on.

## Considered Options

1. **DISA STIG primary, CIS Benchmark secondary, STIG wins conflicts.**
2. **CIS Benchmark primary, STIG secondary, CIS wins conflicts.**
3. **Both, equal weight, per-item per-conflict decisions.**
4. **Neither — no formal compliance baseline.**

## Decision Outcome

Chosen option: **Option 1, DISA STIG primary with CIS Benchmark as secondary, STIG wins conflicts.**

The K8s-layer benchmarks that apply:
- **DISA Kubernetes STIG** (DISA STIG library, V2R3 at time of writing) — primary framework. Item IDs of the form `V-XXXXXX`.
- **CIS Kubernetes Benchmark v1.10.x** — secondary framework. Item IDs of the form `X.Y.Z`. Where STIG is silent, CIS applies. Where they overlap, the stricter STIG wording governs.
- **CIS Containerd Benchmark v1.0.x** — covers the container runtime layer.

The workload/Helm-layer benchmarks that apply per addon:
- **DISA Application Security and Development STIG** — general application hardening (logging, error handling, input validation principles).
- **CIS NGINX Benchmark** — applies to `ingress-nginx`.
- **Helm-specific security best practices** — chart pin discipline, no `:latest`, image-digest pinning (Renovate enforces).
- Workload-specific guides (Cilium's own security posture document, Longhorn's hardening guide) where the upstream publishes them.

The cluster-policy-layer mechanisms that enforce STIG/CIS items at admission time:
- **PodSecurity Standards** (active: `baseline` enforce, `restricted` audit/warn) — STIG `V-242391`/`V-242392` and CIS `5.2.x`.
- A future Kyverno or OPA Gatekeeper deployment **may** be considered for items PodSecurity can't enforce (image-signature verification, label requirements). Deferred pending demonstrated need.

### Conflict resolution rule

Where DISA STIG and CIS Benchmark disagree on a specific item's required value:
1. STIG wording is canonical.
2. The PR that lands the item cites both the STIG item ID and the CIS item ID, notes the conflict, and applies the STIG value.
3. The accepted-deviation table below tracks items where neither the STIG nor CIS value is applied (operator choice + rationale).

### Talos architectural N/A items

The following CIS Distribution Independent Linux Benchmark categories are declared **N/A — Talos architecture**, requiring no further consideration in implementing PRs:
- Filesystem mount options on `/tmp`, `/var/log`, etc. (Talos manages its own filesystem layout, immutable)
- `/etc/passwd`, `/etc/shadow`, `/etc/group` permissioning (no `/etc/passwd` exists)
- SSH server configuration (no SSH server)
- Bootloader passwords (Talos boots immutable images)
- AIDE, AppArmor/SELinux per-binary policy (Talos uses its own LSM posture)
- cron job permissions (no `cron`)
- Package manager audit trails (no package manager)

Sidero's [Talos Security](https://www.talos.dev/v1.12/learn-more/talos-linux-security/) document is the authoritative reference for Talos's deliberate departures from a conventional Linux baseline.

## Pros and Cons of the Options

### Option 1: STIG primary + CIS secondary, STIG wins (chosen)

- **Good, because** STIG is the strictest published standard and the policy framing demands "greatest extent possible" compliance.
- **Good, because** any environment that later requires DoD compliance is mostly there already; downgrading-to-CIS-only is straightforward if scope shrinks.
- **Good, because** kubescape supports CIS K8s Benchmark natively and is API-based (compatible with Talos's immutable file layout); STIG items not in CIS are added as per-PR review items.
- **Bad, because** STIG items not covered by automated tooling (much of the workload layer) require per-PR manual review, which is slower.
- **Bad, because** some STIG items are FIPS-140 oriented (cryptographic module validation) which is impractical at a homelab scale and requires explicit deviation.

### Option 2: CIS primary, STIG secondary

- **Good, because** CIS-first plays to the tooling: most K8s compliance scanners (kubescape, kube-bench, Trivy) ship CIS rule packs out of the box.
- **Bad, because** "as STIG/CIS compliant as possible" implies STIG ceiling, not floor. Choosing CIS primary leaves the stricter STIG items as optional add-ons.

### Option 3: Per-item conflict decisions, both equal weight

- **Good, because** maximally rigorous: every conflict gets its own consideration.
- **Bad, because** scales poorly with the number of items (hundreds of STIG findings, hundreds of CIS items, dozens of conflicts). Slows every PR.

### Option 4: No baseline

- **Bad, because** rejects the operator's stated policy.

## Confirmation

Adherence to this ADR is confirmed by the following mechanisms. The wording `MUST`, `SHOULD`, and `MAY` follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) conventions.

1. **Per-PR review.** Every PR that adds or modifies a Talos machine config, Helm release, K8s manifest, or in-cluster workload MUST include a brief comment in the commit body OR ADR linking the change to applicable STIG/CIS items it addresses. Pattern: `Addresses STIG V-242391, CIS 5.2.6.` If the change is compliance-neutral, the commit body MUST say so explicitly: `Compliance: neutral (no STIG/CIS item affected).`
2. **Continuous scanning.** [`kubescape`](https://kubescape.io/) runs daily via `.github/workflows/kubescape.yaml` against the live cluster (CLI mode, API-based — Talos has no in-cluster Job filesystem to mount). Scan output is SARIF, uploaded to GitHub Code Scanning under category `kubescape-cis`. Per-finding state (`Open`, `Fixed`, `Dismissed`) is tracked by Code Scanning natively; there is intentionally no in-repo baseline file. See [`docs/compliance/README.md`](../../compliance/README.md) for the operator triage flow. The choice of kubescape over `kube-bench` is itself a Talos-fit decision: kube-bench reads node filesystem paths (`/etc/kubernetes/...`, `/var/lib/kubelet/config.yaml`) that Talos's immutable layout doesn't expose; kubescape queries the K8s API.
3. **Accepted deviations table.** Items that are deliberately non-compliant MUST be recorded in the table below with the STIG/CIS ID, the chosen value, the rationale, and a review-by date. Dismissals in the Code Scanning UI MUST cite the corresponding row in this table.
4. **No silent failures.** If kubescape reports a new `Open` finding, the PR that caused the regression MUST be revisited within 7 days — either reverted, remediated (next scan auto-marks the finding `Fixed`), or formally dismissed in Code Scanning with a matching deviation row added to this ADR's table.
5. **Editorial rule.** Adoption or removal of an additional benchmark (e.g., adding NIST 800-190 container security, dropping STIG in favor of CIS-only) is itself a policy decision and MUST be a superseding repo-tier ADR.

## Accepted deviations (as of ADR landing)

The following items are deliberately not in compliance with the strict STIG/CIS reading. Each is listed with the rationale already recorded in the relevant prior commit/ADR.

| Item | Framework refs | Configured value | Rationale | Reference | Review-by |
|---|---|---|---|---|---|
| `controllerManager.extraArgs.bind-address` | CIS 1.3.7, STIG V-242385 | unset (defaults to `127.0.0.1`) | CIS *recommends* `127.0.0.1` — this is COMPLIANT, not a deviation. Item retained here as a reminder that re-introducing `0.0.0.0` for Prometheus scraping later requires firewall scoping. | commit `2afcd91` | When Prometheus lands |
| `scheduler.extraArgs.bind-address` | CIS 1.4.2, STIG V-242384 | unset (defaults to `127.0.0.1`) | Same as above — currently COMPLIANT. | commit `2afcd91` | When Prometheus lands |
| `etcd.extraArgs.listen-metrics-urls` | CIS 2.x, STIG V-242379 | unset (defaults to loopback) | Same as above — currently COMPLIANT. | commit `2afcd91` | When Prometheus lands |
| `--kubelet-insecure-tls` on metrics-server | CIS 5.7.x | **removed** (commit `d13dc7a`) | This deviation is *resolved* — listed here for historical context. metrics-server now validates kubelet's cluster-CA-signed serving cert. | commits `00ba686`, `d13dc7a` | Resolved |
| `enforce_admins: false` on repo rulesets | CIS 5.7.x (process control) | Admin bypass allowed | Single-maintainer repo with single CODEOWNER; allowing admin bypass is the only way to merge without a second human. Mitigated by the etcd snapshot + drift detection trail. | Branch Safety + Pull Request Gate rulesets | Reconsider if a second maintainer joins |
| `:cilium` PodSecurity exemption | CIS 5.2.x | not applied (commit `6724c09`) | Cilium runs in `kube-system` (default-exempted); the `cilium` namespace doesn't exist. The exemption was a misconfiguration. COMPLIANT as-is. | commit `6724c09` | N/A |
| `machine.certSANs` + `apiServer.certSANs` (explicit) | STIG V-242391 | not applied (commit `9974cb7`) | Talos defaults already cover every IP the live clients use. Explicit certSANs would cause cert reissue with zero functional change. COMPLIANT as-is. | commit `9974cb7` | When new TLS clients are added |
| Public DNS / NTP fallbacks | CIS 5.7.x indirect | not applied (commit `44fd296`) | Gateway provides DNS+NTP without incident for 51 days. Adding public fallbacks adds egress logging and lookup latency. Operator-controlled gateway is preferable. | commit `44fd296` | If gateway becomes unreliable |
| `rotate-server-certificates` was previously deferred | CIS 4.2.12, STIG V-242410 | **enabled** (commit `6ba7586`) | Resolved — kubelet now creates CSRs auto-approved by `postfinance/kubelet-csr-approver` ([ADR-0005](0005-kubelet-csr-approver.md)). | commits `6c9a594`, `6ba7586` | Resolved |
| Default-deny `NetworkPolicy` | CIS 5.3.2, STIG V-242425 | not configured | Not addressed yet. Requires per-workload egress audit; planned for a future cycle. | (none yet) | 2026-08-26 |
| Image signature verification (cosign / sigstore) | STIG V-242414 | policy engine in progress; image verification policy pending | ADR-0010 adopts Kyverno as the policy engine. Signature/SBOM verification remains pending until audit-mode policies and attestor rules land. | [ADR-0010](0010-adopt-kyverno-policy-engine.md) | 2026-08-26 |
| Pod-level `securityContext` audit | CIS 5.2.x | partial (PodSecurity admission enforces `baseline`) | Workloads inherit chart defaults. Per-addon audit happens during each migration cycle to Flux. The kubelet-csr-approver and metrics-server HelmReleases use chart-default `securityContext`s which are aligned with the `restricted` PSS profile already. | per-addon HelmReleases | Ongoing per addon |

## Consequences

### Positive

- Every future configuration decision has a framework to be measured against.
- The deviations table makes compliance shortfalls visible rather than implicit.
- Compliance auditing becomes a continuous, automated process once kube-bench is deployed (follow-up cycle).
- New addon migrations naturally include a STIG/CIS impact assessment as part of their HelmRelease commit.
- The cluster is positioned for any future contractual compliance requirement without a massive re-engineering effort.

### Negative

- Every PR carries additional review overhead: the commit body must address STIG/CIS impact.
- Some operationally-convenient changes will become deferred or rejected on compliance grounds, slowing iteration speed.
- The kubescape scan adds a daily GitHub Actions workflow run and the self-hosted runner must reach the cluster API.
- Manual review of STIG items kubescape doesn't cover (workload-layer findings) is non-trivial for someone unfamiliar with the framework.

### Neutral

- The compliance posture is *aspirational*, not contractual. Items where strict compliance would break operational reality are deferred with documented rationale rather than blindly enforced.

## Assumptions

This decision rests on the following assumptions. If any becomes false, this ADR should be revisited:

1. The DISA Kubernetes STIG continues to be updated and remains applicable to Kubernetes ≥ 1.24.
2. `kubescape` continues to track current CIS K8s Benchmark revisions (the maintainer cadence has been reliable; ARMO is the active maintainer organization).
3. Talos's deliberate architectural departures from a conventional Linux baseline continue to be documented by Sidero, so deviations can be cited rather than re-justified per-PR.
4. The operator (single-maintainer) policy stays "as compliant as possible." If this shifts to "fully compliant" (e.g., for a contract), several of the accepted deviations in the table above require resolution before that contract can be claimed.

## Supersedes

None. This ADR establishes a new policy.

## Superseded by

None (current). If a future ADR adopts a different primary framework (e.g., NIST 800-53 Rev. 5 as primary), this ADR is superseded.

## Implementing PRs

The PR that introduces this ADR introduces only the policy. Implementing PRs (in expected order) will:

1. **Daily kubescape scan workflow.** PR #36 landed the initial CLI-based scan (with S3 storage); follow-up PR refactored to SARIF + GitHub Code Scanning. Status: **completed**.
2. **Per-failing-finding remediation cycles** — each `Open` finding on the Security tab becomes a narrow PR with the STIG/CIS reference cited, or a `Dismiss` action with a matching deviation row in this ADR's table.
3. **ingress-nginx STIG hardening cycle** — first workload-layer remediation, per operator's prior request.
4. **Default-deny NetworkPolicy cycle** — addresses the largest single CIS gap (5.3.2).
5. **Image signature verification cycle** — Step 8a adopts Kyverno as the policy engine ([ADR-0010](0010-adopt-kyverno-policy-engine.md)); follow-up PRs add audit-mode then enforce-mode image signature/SBOM policies for STIG V-242414.

## Related ADRs

- [ADR-0003 (repo)](0003-repo-as-cluster-source-of-truth.md) — establishes the source-of-truth model; this ADR establishes the compliance-baseline model on top of it.
- [ADR-0005 (repo)](0005-kubelet-csr-approver.md) — kubelet serving-cert rotation, already aligned with STIG V-242410.
- [ADR-0006 (repo)](0006-etcd-snapshot-automation.md) — etcd snapshots at-rest encryption, already aligned with STIG V-242379 partial.
- [ADR-0008 (repo)](0008-gitops-via-flux.md) — Flux is the mechanism by which compliance-driven addon changes will land.

## Compliance Notes

This ADR is itself the compliance posture. It does not directly map to a single control because it establishes the framework under which all subsequent controls are evaluated.

| Framework              | Control / Practice ID                              | Potential Evidence Contribution                                                                                              |
| ---------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5  | CA-2 (Control Assessments)                         | This ADR + the kube-bench cron job (follow-up) constitute the cluster's continuous control assessment.                       |
| NIST SP 800-53 Rev. 5  | CM-6 (Configuration Settings)                      | The choice of STIG + CIS as the baseline frameworks satisfies CM-6's "configuration settings established and documented."    |
| NIST SP 800-53 Rev. 5  | RA-5 (Vulnerability Monitoring)                    | kube-bench's continuous CIS K8s Benchmark scan is the vulnerability-monitoring mechanism for the cluster control plane.      |
| NIST SP 800-218 (SSDF) | RV.1 (Identify and Confirm Vulnerabilities)        | Per-PR STIG/CIS review + kube-bench scanning together cover the identify-and-confirm SSDF requirement for cluster releases.   |
