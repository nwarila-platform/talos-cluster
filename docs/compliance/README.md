# Compliance scanning

This directory holds the cluster's compliance posture artifacts and operator
runbook. The scanning framework itself is defined in
[ADR-0009](../decision-records/repo/0009-stig-cis-compliance-baseline.md).

## What's scanned

[Kubescape](https://kubescape.io/) runs daily via `.github/workflows/kubescape.yaml`
and scans this cluster against the **CIS Kubernetes Benchmark v1.10.0**. Each
scan emits a SARIF report covering ~129 CIS controls and per-resource details
— which Kubernetes objects fail which controls.

Why Kubescape and not [kube-bench](https://github.com/aquasecurity/kube-bench):
kube-bench reads node filesystem paths (`/etc/kubernetes/...`,
`/var/lib/kubelet/config.yaml`, `/etc/systemd/...`) that Talos's immutable
file layout doesn't expose. Kubescape queries the Kubernetes API instead,
which is the right shape for Talos. See [ADR-0009](../decision-records/repo/0009-stig-cis-compliance-baseline.md)
for the full reasoning.

## Where findings live

| Location | What it holds | Why there |
|---|---|---|
| GitHub `Security` → `Code scanning` (category `kubescape-cis`) | Every finding, per-resource, with `Open` / `Fixed` / `Dismissed` state | Native security-artifact surface; auditor-readable; state survives across runs without an in-repo baseline file. |
| Workflow run logs | Step output, SARIF parse confirmation, kubescape CLI version | Debugging the scan pipeline itself, not for finding triage. |

There is intentionally no `kubescape-baseline.json` checked into this repo.
GitHub Code Scanning maintains per-finding state natively (fingerprinted by
rule + location), which is the right place for it. Adding an in-repo
baseline file would duplicate that state and create a PR-update ritual for
no operational benefit.

## How regression detection works

GitHub Code Scanning tracks each finding's state automatically:

- **Open** — finding is currently failing in the most recent scan.
- **Fixed** — finding was failing previously, is no longer reported. Code
  Scanning detects this when the rule+location fingerprint disappears from
  the SARIF upload.
- **Dismissed** — operator explicitly marked the finding as `Won't fix`,
  `Used in tests`, or `False positive`. Dismissed findings stay suppressed
  on subsequent scans unless re-opened.

A new failing CIS control surfaces as a new `Open` alert on the Security
tab. The repo's notification settings (configurable per-watcher in GitHub
UI) decide whether that triggers an email or in-app notification.

The workflow itself fails only when the scan pipeline breaks (kubescape CLI
missing, kubeconfig missing, SARIF malformed) — *not* on individual findings.
Findings are the data; the workflow's job is to keep the data flowing.

## How to triage a new failure

1. Open `Security` → `Code scanning` on the GitHub repo. Filter by tool
   `Kubescape` (or click the `kubescape-cis` category).
2. Open the new `Open` alert. The alert body shows: the CIS control ID, the
   Kubernetes object that failed it, and Kubescape's remediation text.
3. Decide: **remediate** or **dismiss**.
   - **Remediate**: open a narrow PR fixing the configuration. Commit body
     cites the CIS item ID per [ADR-0009](../decision-records/repo/0009-stig-cis-compliance-baseline.md) §Confirmation §1.
     Next scheduled scan will auto-mark the alert as `Fixed`.
   - **Dismiss**: in the Code Scanning UI, set the alert to `Dismiss alert`
     with reason `Won't fix` and a one-line note pointing at the accepted
     deviation in ADR-0009. Then update the deviations table in ADR-0009
     with the control ID, the configured value, the rationale, and a
     review-by date.

No baseline file to update. No PR required to "accept" the new state —
Code Scanning is the system of record.

## Running a scan locally

```bash
# Ensure the kubescape CLI is installed (v4.0.8+ recommended).
# Windows: download kubescape_X.Y.Z_windows_amd64.exe from
#   https://github.com/kubescape/kubescape/releases
# Linux:   download kubescape_X.Y.Z_linux_amd64

# Ensure .s3/configs/kubeconfig is present (`make s3-pull` if not)
bash scripts/kubescape-scan.sh
```

The script writes `kubescape.sarif` in the repo root (gitignored by the
deny-all rule). Local runs do not upload to GitHub Code Scanning — only the
CI workflow does, because uploads require the `GITHUB_TOKEN` with
`security-events: write` that GitHub Actions provides.

To preview the SARIF locally, use any SARIF viewer
(e.g., [microsoft/sarif-vscode-extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer))
or jq:

```bash
jq '.runs[0].results | length' kubescape.sarif       # total results
jq '.runs[0].results[] | .ruleId' kubescape.sarif    # rule IDs
```

## What this scanner does NOT cover

- **STIG-specific items not in CIS K8s Benchmark.** Per [ADR-0009](../decision-records/repo/0009-stig-cis-compliance-baseline.md),
  STIG is the primary framework, but most automated tooling targets CIS.
  STIG items beyond CIS coverage (FIPS-140 cryptographic module validation,
  certain audit-retention requirements) are tracked via manual per-PR
  review, not via this workflow.
- **Talos-OS-layer controls.** Talos's immutable file system means most
  CIS Distribution Independent Linux items don't apply. See ADR-0009's
  "Talos architectural N/A items" section.
- **Workload-layer hardening per addon.** Kubescape's NSA framework
  covers some pod-level security context items, but ingress-nginx
  configuration, Cilium configuration, etc. require their own per-addon
  review (CIS NGINX Benchmark, Cilium hardening guide).
- **Runtime threat detection.** Kubescape is a periodic snapshot scanner,
  not a runtime monitor. Tools like Falco would fill that gap; not yet
  deployed.

## See also

- [ADR-0009](../decision-records/repo/0009-stig-cis-compliance-baseline.md) — establishes the compliance framework, conflict resolution, and accepted-deviations table.
- [scripts/kubescape-scan.sh](../../scripts/kubescape-scan.sh) — the scan orchestrator.
- [.github/workflows/kubescape.yaml](../../.github/workflows/kubescape.yaml) — the scheduled scan workflow.
- [GitHub Code Scanning docs](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/about-code-scanning-alerts) — alert states, dismissal workflow, notification settings.
