# `scripts/` — control-surface manifest

This is the human-auditable index of every script in this repo: what it protects or does,
whether a **native** platform feature already covers it, and a standing **verdict**. The
self-management model bets that "CI green ⇒ safe to merge" — that bet is only manageable if
the machinery making it is itself legible on one page. This file is that page.

**Rule of thumb applied throughout:** a script earns its place only if it closes a concrete
failure/attack/drift that no native tool (Kyverno webhook + PolicyReports, Flux
reconcile/health/prune, `talosctl validate`/`apply-config --dry-run`, `flux check`, Pod
Security Admission, `renovate-config-validator`, `actionlint`, SOPS+Flux) already covers —
**and** does it legibly. Guards that merely police a duplication the repo created on purpose
should be fixed at the root (single source of truth), not guarded.

Verdicts: **KEEP** (load-bearing, no native equivalent) · **SIMPLIFY** (justified but
oversized/reinvents a wheel) · **CONSOLIDATE** (merge with a sibling / a shared lib) ·
**CUT** (theater or fully native-covered or dead) · **DEMOTE** (completed, move to on-demand)
· **WIRE** (real but not invoked anywhere). Last audited: 2026-07-18 (6-auditor parallel pass).

> Every `check-*.py` guard ships a companion `*.selftest.py` (a "does the guard bite?" test)
> run in CI; those are not listed separately.

---

## CI guards — supply-chain / images

| Script (lines) | Protects | Native alternative | Verdict |
|---|---|---|---|
| `check-image-signature-enforcement.py` (1676) | First-party GHCR images must be signature-verified by a policy pinned to exact shape (offline Sigstore pins, first-party CEL scoping, fail-closed webhook, exempt-ns surface) — can't be gutted with green CI | Kyverno validates policy *schema* + reports runtime pass/fail, but neither pins the intended *posture* in source → **NO** | **SIMPLIFY** — carries two enforcement models; retire the legacy `verifyImages` half (= PR-C2, ≈halves it) + move shared parser to `scripts/lib/` |
| `check-image-digest-sync.py` (373) | No image pinned to two different digests across files; first-party images use digests not mutable tags | Renovate `pinDigests` keeps digests *fresh* but doesn't detect *divergent* pins → **PARTIAL** | **CONSOLIDATE** — its 9-function YAML/image parser is copy-pasted from the sig guard → `scripts/lib/` |
| `check-sigstore-pin-verification.py` (212) | Daily: the enforced policy is present+Ready and every first-party sig still verifies against the pinned keys (rotation drift) | Consumes Kyverno's own PolicyReport ground truth (the *correct* native use) | **KEEP** — thin, honest, reads native truth instead of rebuilding cosign/TUF |

## CI guards — Vault (root-equivalent security)

| Script (lines) | Protects | Native alternative | Verdict |
|---|---|---|---|
| `check-vault-policy-no-escalation.py` (878) | Managed Vault policy grants can't reach the management plane (allowlist + ACL path-subsumption `covers()`) — config-writer is root-equivalent | Vault doesn't constrain authored policies; nothing parses HCL path-subsumption → **NO** | **KEEP** — simplify only the bespoke HCL tokenizer (swap for a vetted lib; never touch `covers()`) |
| `check-vault-config-operator-bootstrap-invariants.py` (416) | The operator's own identity + break-glass `vault-admin` are never self-managed/self-escalating (ADR-0028 bootstrap paradox) | none → **NO** | **KEEP** — highest-stakes anti-self-escalation invariant |
| `check-vault-config-reference-safety.py` (417) | Every Vault-object reference (role→policy, issuer→mount, …) resolves to an in-git provider (S7 prune safety) | cross-CRD semantic refs are opaque to Flux/kustomize → **NO** | **KEEP** |
| `check-vault-config-terminating.py` (118) | Daily: no managed CR stuck Terminating >30m (fire-and-forget prune blind spot, #133) | Flux reports the Kustomization Ready while the object hangs → **NO** | **KEEP** |
| `check-vault-fold-invariants.sh` (72) | Vault stays folded into `apps/vault`; can't be silently recreated as a `deploy-*` repo | none (valid YAML to native tools) → **NO** | **KEEP** |
| `check-live-vault-config-invariants.sh` (62) | Live Vault never enables unauthenticated generate-root (ADR-0019) | Kyverno runtime + this source-pin = deliberate defense-in-depth → **PARTIAL** | **KEEP** |
| `check-vault-restore-validator-boundaries.sh` (1609) | DR restore-validator can't reach live `data-vault` / escalate (ADR-0020/23/24) | ~40% source-pins (image digest, CronJob suspend, closed-world footprint, Longhorn scratch-only RBAC) native can't do; **~60% re-pins securityContext/PSA fields already enforced by restricted-PSA + the sibling Kyverno policy** → **PARTIAL** | **SIMPLIFY** — drop the PSA/Kyverno-redundant ~60%, keep the ~10 real source-pins |
| `vault-config/verify-adoption-parity.py` (516) | Live Vault == git CRs, byte/field-exact (CP-4 adoption acceptance proof) | operator `ReconcileSuccessful` never proves byte parity → **NO** | **DEMOTE** — adoption complete; make it an on-demand drift check or archive |
| `vault-config/seed-operator-bootstrap.sh` (219) | Codifies the one irreducible out-of-band bootstrap seed with read-back parity (ADR-0028) | must NOT be GitOps'd → **NO** | **KEEP** |

## CI guards — Flux / config / workflow

| Script (lines) | Protects | Native alternative | Verdict |
|---|---|---|---|
| `check-flux-crd-served-versions.py` (369) | Flux CRD served/storage versions match a reviewed map (silent reconcile-stall class, #246) | `flux check` doesn't diff served versions vs a map → **NO** | **KEEP** — share the duplicated YAML-node boilerplate via `scripts/lib/` |
| `check-renovate-coverage.py` (260) | Every `# renovate:` annotation is covered by a customManager (orphaned pins that silently never update) | `renovate-config-validator` validates syntax only, not coverage → **NO** | **KEEP** |
| `check-workflow-health.py` (342) | Weekly: no scheduled workflow is persistently red (a silently-dead pipeline) | GitHub has no "workflow red N times" alert; actionlint is static lint → **NO** | **SIMPLIFY** — de-scaffold (5 dataclasses + ASCII table around a 2-condition boolean) |

## CI guards — nodes / Talos

| Script (lines) | Protects | Native alternative | Verdict |
|---|---|---|---|
| `check-node-patch-consistency.py` (360) | Per-node patch static-IP/disk/VIP match inventory (wrong IP → node reboots unreachable, no OOB recovery) | `talosctl validate` is per-file schema-only, can't catch cross-file semantic drift → **NO** | **KEEP** — closes a real silent-brick |
| `check-node-inventory-sync.py` (434) | Human `systems` table matches `config.env` | none (repo-internal), but it guards a self-created duplication of config.env's node data | **SIMPLIFY** — shrink hard (6-row table), share the `systems` parser, generate the overlapping columns to remove the dup |
| `test-talos-drift-readonly.py` (119) | Unit tests for the in-cluster `talos-drift` CronJob | N/A (tests) | **KEEP** |
| `render-talos-drift-expected.py` (76) | Generates the secret-free `expected.env` the drift CronJob consumes; `--check` fails if stale | none (bespoke projection a pod can't derive from secret-bearing config.env) → **NO** | **KEEP** — the "generate + freshness-guard" pattern done right |
| `diff-vs-live.py` (199) | Structural diff of regenerated machineconfig vs live | `talosctl apply-config --dry-run` (but broken for multi-doc configs, siderolabs/talos#8885) → **PARTIAL** | **SIMPLIFY** — delegate the diff to Talos where it works; keep custom only for the multi-doc gap |

## CI guards — networking

| Script (lines) | Protects | Native alternative | Verdict |
|---|---|---|---|
| `check-firewall-management-ports.py` (151) | Talos host firewall keeps apid (50000) + trustd (50001) — omitting trustd stranded worker cert renewal once | `talosctl validate` is schema-only → **NO** | **SIMPLIFY** — delete the ~55-line hand-rolled YAML parser; PyYAML is already a dep |
| `check-runner-cnp-github-parity.py` (216) | The 2 ARC runner-egress CNPs expose an identical GitHub `toFQDNs` set | none for CNP parity — but it guards a copy-paste of the same rule in two files | **SIMPLIFY** — unify the 2 CNPs via a shared kustomize component ⇒ the guard evaporates |

## CI guards — Helm values-sync (a consolidation target)

These three are near-identical and guard a **self-created duplication**: `addons/*/values.yaml`
are human-readable reference copies that **Flux never applies** (it reconciles the inline
HelmRelease `spec.values`). ADR-0022 already logs the two-copy duplication as a "Negative".
The right fix is to remove the duplication (helm `valuesFrom` a kustomize-generated ConfigMap =
single source) so the guards evaporate, or failing that collapse 3→1 parameterized guard.

| Script (lines) | Protects | Native alternative | Verdict |
|---|---|---|---|
| `check-longhorn-values-sync.py` (161) | `addons/longhorn/values.yaml` ≡ Longhorn HelmRelease `spec.values`; `LONGHORN_VERSION` ≡ chart | Flux applies only `spec.values`; the addon file is unconsumed → **PARTIAL** (fix = kill the dup) | **CONSOLIDATE** |
| `check-cilium-values-sync.py` (160) | same, for Cilium (+ `CILIUM_VERSION`) | same → **PARTIAL** | **CONSOLIDATE** |
| `check-kubelet-csr-approver-values-sync.py` (111) | same, for kubelet-csr-approver (no version key) | same → **PARTIAL** | **CONSOLIDATE** (the version-optional shape = the template for the merged guard) |

## CI guards — docs / text / quality

| Script (lines) | Protects | Native alternative | Verdict |
|---|---|---|---|
| `check-sops-encrypted.py` (273) | No plaintext secret committed under `*.sops.*` naming | **Flux passes a plaintext `*.sops.yaml` through UNCHANGED** (does not fail closed); gitleaks is pattern-based → **NO** | **KEEP** — the only fail-closed catch on a real secret-leak path; do not cut |
| `check-no-placeholder-leak.sh` (54) | No unresolved `placeholder` survives render (a tenant overlay missing a `replacements` block admits at Kyverno but breaks VSO at runtime) | kustomize renders unreplaced placeholders happily → **NO** | **KEEP** |
| `check-text-encoding.py` (64) | No UTF-8 BOM / Windows-1252 mojibake in tracked text (Windows→Linux migration residue) | `.editorconfig`/pre-commit not CI-enforced here; mojibake bespoke → **PARTIAL** | **KEEP** — tiny, hermetic |
| `render-readme-versions.py` (260) | README version pins derived from source of truth; `--check` fails if stale | Right pattern, but 10 brittle prose-anchored regexes | **SIMPLIFY** — move prose pins into a `README.md.tmpl` template |
| `render-dr-schedule-values.py` (325) | DR schedule/retention numbers rendered from canonical manifests into 11 target doc lines; `--check` fails if stale | none; generation is the repo's preferred source-backed docs pattern | **KEEP** — additive precondition for cutting the curated schedule-claim guard |
| `render-scripts-readme-counts.py` (164) | scripts/README line-count cells derived with `wc -l` semantics; `--check` fails if stale | none; generation removes the hand-maintained count drift class | **KEEP** |
| `check-doc-links.py` (187) | No broken *relative* markdown links | `lychee --offline` / markdown-link-check do exactly this → **FULLY** | **CONSOLIDATE** — replace with `lychee --offline` (a pinned binary like actionlint) |
| `check-doc-schedule-claims.py` (599) | Doc schedule *prose* ("daily", "retain 14") matches manifest cron/retain fields | none, but it guards documentation *adjectives* and needs manual claim-curation to fight manual drift | **CUT** — theater; fold the old guard's 11 numeric anchors / 8 doc lines / 5 source fields, plus previously unguarded V6 local retention, into the 6-field render-generation pattern; delete the rest |

## Operational / lifecycle (thin `talosctl`/`aws`/Factory wrappers — zero-manual)

| Script (lines) | Does | Native alternative | Verdict |
|---|---|---|---|
| `generate.sh` (225) | Per-node machineconfig gen: multi-doc append + hostname injection + SecureBoot branch | `talosctl gen config` can't do multi-doc/hostname/SB → **thin-justified** | **KEEP** |
| `apply.sh` (118) | CP-safe ordered `apply-config` (bootstrap CP last) + atomic preflight | `apply-config` is per-node only → **thin-justified** | **KEEP** |
| `upgrade.sh` (189) | Rolling ordered upgrade + health-gate via a non-target anchor CP | no native rolling/dry-run upgrade (siderolabs/talos#10804) → **thin-justified** | **KEEP** |
| `bootstrap.sh` (100) | One-time etcd bootstrap → health → kubeconfig, run-once guard | chained `talosctl` calls → **thin-justified** | **KEEP** |
| `health.sh` (91) | Health snapshot: `talosctl health` + version table + `kubectl` listing | mostly `talosctl health` (thinnest wrapper) → **thin-justified** | **KEEP** |
| `drift-check.sh` (84) | Machineconfig drift (repo vs live) — the *only* machineconfig-drift detector | native `--dry-run` broken for multi-doc (#8885) → **thin-justified** | **WIRE** — add a `make drift-check` target; fix its mis-attributed header comment |
| `s3-sync.sh` (56) | `.s3/` push/pull with KMS, deliberately no `--delete` (lockout-safety) | `aws s3 sync` + a real safety decision → **thin-justified** | **KEEP** |
| `build-maintenance-iso.sh` (322) | SecureBoot maintenance ISO via Talos Image Factory API; pins the `ip=…:eno1:off` kernel arg | no native Factory CLI → **thin-justified** | **SIMPLIFY** — drop the 4-parser YAML fallback + awk indentation surgery (use `yq`) |

## Tenancy generators

| Script (lines) | Does | Native alternative | Verdict |
|---|---|---|---|
| `sync-deploy-repos.sh` (783) | Discover `deploy-*` repos → stamp per-tenant zero-touch Flux/Vault overlays (the tenancy contract) | repo-discovery + overlay-stamping is inherently scripted → **NO** | **KEEP** — simplify only the byte-identical `replacements:` block (→ a shared Component) + awk parser (→ `yq`) |
| `onboard-tenant.sh` (140) | Manual bare-envelope scaffold for one tenant (legacy path) | duplicate of `sync-deploy-repos`; consumes the legacy flat `_template/*.tmpl`; has produced **zero** tenants | **CUT** — retire it + the stale `.tmpl` set; fold its one unique bit (pre-create envelope) into the zero-touch generator |
| `open-sync-pr.sh` (131) | Commit sync output as the bot + open/update/close the sync PR | `peter-evans/create-pull-request` covers ~80% → **PARTIAL** | **SIMPLIFY** — keep only the custom token/identity handling if it can't be expressed in the action |

## DR / backup

| Script (lines) | Does | Native alternative | Verdict |
|---|---|---|---|
| `dr/apply-vault-snapshot-backup-live.sh` (520) | Break-glass: provision + *prove* the least-privilege Vault backup credential when the operator isn't running | Velero doesn't do Vault Raft; not a native op → **NO** | **KEEP** — thoroughness is the point of a break-glass proof |
| `backup-handoff-ledger.sh` (146) | Encrypt + stage the gitignored `_handoff/` ledger to S3 (`tar`→`age`→`aws --sse kms`) | thin standard pipe; no native equivalent → **NO** | **KEEP** — unscheduled (operator-run) is the only nit |

## Compliance / kubescape

| Script (lines) | Does | Native alternative | Verdict |
|---|---|---|---|
| `kubescape-scan.sh` (104) | Live-cluster CIS scan → JSON → SARIF → validate (ADR-0009) | thin native `kubescape scan` usage → **NO** | **KEEP** |
| `kubescape-json-to-sarif.py` (195) | Convert cluster-scan JSON → SARIF 2.1.0 with stable fingerprints (Code Scanning state tracking) | `kubescape --format sarif` is **not supported for live-cluster scans** (kubescape#1366) → **NO** | **KEEP** |

---

## Cleanup backlog (the standing cull plan)

Tracked here so the "how do we keep this legible" answer lives in-repo, not in chat history.
Each item lands as its own small, audited, revertible PR.

**Cut (delete outright):**
- `check-doc-schedule-claims.py` (+ selftest) — guards doc adjectives; fold the old guard's 11 numeric anchors / 8 doc lines / 5 source fields, plus previously unguarded V6 local retention, into the 6-field `render-*`; delete the rest.

**Consolidate (remove duplication at the root):**
- **values-sync trio** (`check-longhorn/cilium/kubelet-csr-approver-values-sync.py`) — `addons/*/values.yaml` are not consumed by Flux (it applies inline `spec.values`); fix via helm `valuesFrom` a kustomize-generated ConfigMap ⇒ all 3 guards evaporate, or collapse 3→1 parameterized guard. *(touches HelmReleases → owner-watched)*
- Extract `scripts/lib/` — shared YAML/image helpers (image-digest, image-sig, flux-crd guards) + `nodes.sh` node-map/ordering (apply, upgrade, bootstrap, health).
- `onboard-tenant.sh` + legacy `_template/*.tmpl` → fold into `sync-deploy-repos`/zero-touch.
- `check-doc-links.py` → `lychee --offline`.

**Simplify (keep the invariant, shed bloat):**
- `check-image-signature-enforcement.py` — retire the legacy `verifyImages` half (= PR-C2). *(owner-watched)*
- `check-vault-restore-validator-boundaries.sh` — drop the ~60% redundant with restricted-PSA + the sibling Kyverno policy.
- `check-node-inventory-sync.py`, `check-firewall-management-ports.py`, `check-workflow-health.py`, `render-readme-versions.py`, `diff-vs-live.py`, `build-maintenance-iso.sh`, `check-runner-cnp-github-parity.py` (→ shared CNP component), `open-sync-pr.sh`, `check-vault-policy-no-escalation.py` (HCL tokenizer only).

**Demote / wire:**
- `vault-config/verify-adoption-parity.py` → on-demand drift check or archive.
- `drift-check.sh` → add a `make drift-check` target; fix the mis-attributed header.
