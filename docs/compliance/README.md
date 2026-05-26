# Compliance scanning

This directory holds the cluster's compliance posture artifacts: the current
baseline scan, deviations, and remediation notes. The scanning framework
itself is defined in [ADR-0009](../decision-records/repo/0009-stig-cis-compliance-baseline.md).

## What's scanned

[Kubescape](https://kubescape.io/) runs daily via `.github/workflows/kubescape.yaml`
and scans this cluster against the **CIS Kubernetes Benchmark v1.10.0**. Each
scan produces a JSON report containing:

- An overall **compliance score** (0–100, higher is better).
- Per-control results (`passed`, `failed`, `skipped`) for ~129 CIS controls.
- Per-resource details — which Kubernetes objects fail which controls.

Why Kubescape and not [kube-bench](https://github.com/aquasecurity/kube-bench):
kube-bench reads node filesystem paths (`/etc/kubernetes/...`,
`/var/lib/kubelet/config.yaml`, `/etc/systemd/...`) that Talos's immutable
file layout doesn't expose. Kubescape queries the Kubernetes API instead,
which is the right shape for Talos. See [ADR-0009](../decision-records/repo/0009-stig-cis-compliance-baseline.md)
for the full reasoning.

## Where scans live

| Location | Contents | Retention |
|---|---|---|
| `s3://793496711039-terraform/nwarila-platform/talos-cluster/compliance/kubescape/YYYY-MM-DD/scan-HHMMSSZ.json` | Every scheduled scan, KMS-encrypted | S3 bucket lifecycle (currently unbounded; lifecycle rule recommended in ADR-0006 §Consequences) |
| `docs/compliance/kubescape-baseline.json` (this directory, when present) | The accepted baseline; regression checks diff against it | Updated only via PR after operator triage of a new scan |

## How regression detection works

`scripts/kubescape-scan.sh`:
1. Runs `kubescape scan framework cis-v1.10.0` against the live cluster.
2. Uploads the JSON to S3.
3. Compares the scan's `summaryDetails.score` against the score in
   `docs/compliance/kubescape-baseline.json`.
4. Exits 1 if the scan score is more than 1.0 point below the baseline
   (the configured tolerance, set in the script).

The workflow opens a GitHub issue labelled `compliance,automated` when a
scheduled run exits 1. Manual `workflow_dispatch` runs that fail still
exit 1 but don't open issues (the operator is already watching the run).

## How to triage a new failure

1. Read the new scan JSON from S3 (the issue body links to the run output).
2. Identify the new failing control (compare against the baseline).
3. Decide: **remediate** or **add a deviation**.
   - **Remediate**: open a narrow PR fixing the configuration. Commit body
     cites the CIS item ID per [ADR-0009](../decision-records/repo/0009-stig-cis-compliance-baseline.md) §Confirmation §1.
   - **Add a deviation**: update the deviations table in ADR-0009 with the
     control ID, the configured value, the rationale, and a review-by date.
4. After remediation (or deviation acceptance), update
   `docs/compliance/kubescape-baseline.json` to the new state. The next
   scheduled run compares against this updated baseline.

## How the baseline gets updated

The baseline file lives in git, protected by the same Ruleset as the rest
of `main`. Updates require a PR with:
- The new scan JSON (copied from S3) as the file contents.
- A commit body explaining why the baseline changed (which controls
  moved, why, citing the remediation PR or the deviation ADR update).

Updates are **never automated**. The workflow doesn't commit back to the
repo. Operator review is the gate.

## Running a scan locally

```bash
# Ensure the kubescape CLI is installed (v4.0.8+ recommended).
# Windows: download kubescape_X.Y.Z_windows_amd64.exe from
#   https://github.com/kubescape/kubescape/releases
# Linux:   download kubescape_X.Y.Z_linux_amd64

# Ensure .s3/configs/kubeconfig is present (`make s3-pull` if not)
bash scripts/kubescape-scan.sh
```

The local run uploads to S3 just like the scheduled workflow does. To run
a scan that does NOT upload (e.g., for ad-hoc exploration), set
`S3_BUCKET=""` in the environment to short-circuit the upload — but the
script doesn't currently support this; running with broken AWS creds will
fail at the upload step.

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
