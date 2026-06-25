# REPORT - Step 153b DR snapshot backup hardening

Branch: codex/vault-snapshot-backup-dr-foundation
PR: #208 updated on the existing branch; no new PR opened; not merged.
Executor: Codex
Date: 2026-06-25

## Fixes

1. NET-1 DNS least privilege
   - Before: dr-backup Cilium L7 DNS allowed `matchPattern: "*"`.
   - After: DNS is limited to `matchName: vault.deploy-vault.svc.cluster.local`.
   - Added `dnsConfig` with `ndots: "1"` to the live proof Job pod spec, with a note that the future standing backup Job needs the same setting.
   - The proof client now refuses Vault standby redirects to pod-internal DNS names and retries the same allowed service FQDN, so the proof remains inside the single-name DNS allow-list.

2. VLP-5 dead 403 detector removed
   - Before: unused `check_403_script` / `check_for_403` string-grep detector existed in the script.
   - After: the dead block is deleted. The only 403 proof remains the strict in-pod `urllib.error.HTTPError` check where `exc.code == 403`.

3. H1 operator port-forward TLS verification
   - Before: `VAULT_SKIP_VERIFY` defaulted to `true` for operator-side admin-token calls over the port-forward.
   - After: `VAULT_SKIP_VERIFY` defaults to `false`.
   - The script extracts the committed `apps/dr-backup/vault-ca-configmap.yaml` `ca.crt` into a temp CA file and verifies the port-forward TLS chain with `check_hostname=False` and `CERT_REQUIRED`, preserving explicit `VAULT_SKIP_VERIFY=true` as an opt-out.

4. H2 admin-token hygiene
   - `VAULT_TOKEN` remains the first/preferred admin token source.
   - Script header and `vault-config/README.md` now require a short-TTL minted admin token, not a standing root token, and document revocation after use.
   - Added opt-in `REVOKE_TOKEN_AFTER=true`, which runs `vault token revoke -self` after a successful proof.

Kept intentionally unchanged: `auth/token/renew-self` and `auth/token/lookup-self` remain in `vault-snapshot-backup.hcl`.

## Live Re-proof

Command: `scripts/dr/apply-vault-snapshot-backup-live.sh`

Sanitized output markers:

```text
POLICY_ROLE_APPLIED_OK
DR_BACKUP_MANIFESTS_APPLIED_OK
VAULT_POD vault-0 phase=Running ready=1/1 restarts_before=1 restarts_after=1 unchanged=true
VAULT_POD vault-1 phase=Running ready=1/1 restarts_before=0 restarts_after=0 unchanged=true
VAULT_POD vault-2 phase=Running ready=1/1 restarts_before=1 restarts_after=1 unchanged=true
VAULT_UNDISTURBED_OK
SNAPSHOT_OK size_bytes=115534
SECRET_READ_403_OK
POLICY_LIST_403_OK
TOKEN_CREATE_403_OK
PROOF_JOB_DELETING
PROOF_COMPLETE_OK
```

Result: PASS under `matchName` DNS policy plus proof pod `ndots:1`. Snapshot size was nonzero; snapshot contents were not printed or stored in the report.

## Static Verification

- `git diff --check`: PASS
- `kubectl kustomize clusters/talos-cluster/apps/dr-backup`: PASS
- `kubectl kustomize clusters/talos-cluster/apps`: PASS
- `bash -n scripts/dr/apply-vault-snapshot-backup-live.sh`: PASS

## Forward-tracked Items

- C4: `vault-config` is live-applied, not Flux-reconciled, with no drift guard. Track to ADR-0019 / planned Kyverno guard in DR-PLAN step 10.
- VLP-1: no Role pinning who can spawn `dr-backup` Jobs. Current exposure remains cluster-admin plus Flux only; enforce when standing backup Jobs land in DR-PLAN step 5, preferably via GitHub Environment plus guard.
- NET-4: document that the service-account-bound Kubernetes auth role is the authoritative gate, not the network label.

## Commits And Signature

- Fix commit: `b6ce81981147f66b951abb7db037e2f53f1e4c64` (`Harden vault snapshot backup proof`)
- Signature: `Good "git" signature for 33955773+NWarila@users.noreply.github.com with ECDSA key SHA256:UAsMtOhQwpR/duoYjPY3LSw4a905Dx29QPGGXCTkhGY`

This report is committed separately after the fix commit so it can record the signed fix SHA without a self-referential hash.