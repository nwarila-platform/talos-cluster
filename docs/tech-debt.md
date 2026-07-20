# Technical Debt Register

Known, deliberately-deferred gaps. Each entry records the gap, why it was
deferred, its impact, and the concrete options to close it. Decisions live in
the ADRs; this register tracks the *debt* those decisions leave behind.

| ID | Title | Status | Priority |
| --- | --- | --- | --- |
| TD-0001 | Cilium + Kyverno images cannot be signature-enforced at admission | Open | **High** |
| TD-0002 | Flux image-signature enforcement deferred | Open | Medium |
| TD-0003 | Strict Diataxis quadrant-directory layout not implemented | Open | Medium |
| TD-0004 | Org-ADR drift gate neutralized pending allowlist restoration | Resolved | **High** |
| TD-0005 | Stage-1 offsite/offline copy remains future work | Open | Medium |
| TD-0006 | Backup-target transport and share-at-rest crypto remain accepted residuals | Open | Low |
| TD-0007 | NAS administrative and appliance isolation trust boundary accepted residuals | Open | Low |
| TD-0008 | Selector-bound Vault auth roles cannot be operator-reconciled (vault-config-operator CRD gap) | Open | Medium |
| TD-0009 | First-party image admission enforcement was temporarily non-blocking | Resolved | **High** |
| TD-0010 | kube-system remains outside the declared PSA floor | Open | **High** |
| TD-0011 | Tenant image pulls use an org-wide classic PAT that cannot be repo-scoped | Open | **High** |

---

## TD-0001 — Cilium + Kyverno images cannot be signature-enforced at admission

**Opened:** 2026-06-11 · **Status:** Open · **Priority:** High ·
**See:** [ADR-0010](decision-records/repo/0010-adopt-kyverno-policy-engine.md)

### Gap
Cosign image-signature verification for first-party images is enforced at
`[Deny]`/`Fail` by `ImageValidatingPolicy/verify-first-party`. Separately,
**Cilium** (`quay.io/cilium/*`) and **Kyverno** (`ghcr.io/kyverno/*`) are
**Audit-only** — an unsigned/tampered Cilium or Kyverno image is *reported* but
not *blocked* at admission. (Flux is a separate item — see TD-0002.)

### Root cause (precise)
The **tested Kyverno admission paths do not provide a working Enforce-mode
verification path for the Cilium/Kyverno upstream image *signature* artifacts**,
because those artifacts are stored in a registry format Kyverno's verifier does
not discover/consume. Local `cosign verify` succeeds; Kyverno admission
verification fails for the **exact digest-pinned** images under Enforce.
**`cosign` CLI working does not imply Kyverno admission works** — Kyverno does not
shell out to the local cosign; it calls the cosign *library* with its own
discovery path. This is **not** egress (Step 47 proved reachability) and **not**
merely an alternate signature repository.

Two distinct failure classes (do not conflate):
- **(A) Legacy `ClusterPolicy verifyImages` cannot enforce these artifacts.**
  Cilium publishes signatures as **OCI 1.1 referrers / Sigstore bundles**
  (`application/vnd.dev.sigstore.bundle.v0.3+json`); Kyverno publishes to the
  separate `ghcr.io/kyverno/signatures` repo as **digest-keyed bundle tags
  without the legacy `sha256-<digest>.sig` suffix**. Kyverno's verifier looks for
  the legacy `.sig` tag and reports `no signatures found`. Upstream evidence:
  cosign's `Verify*` lacks an OCI-1.1-referrer discovery path, and Kyverno's
  verify path inherits that limitation ([cosign #4708]).
- **(B) The newer `ImageValidatingPolicy` (IVP) / VAP path is UNPROVEN in this
  cluster** — a separate plumbing problem, not a format conclusion. In the spike
  even a *deliberately-always-false* sanity IVP emitted **no** admission
  warning/PolicyReport (status-controller update conflicts in logs). Before IVP
  can be a fallback, prove a trivial IVP produces admission/reporting results
  (check matchConstraints, namespace filters, operations, `validationActions`,
  webhook activation, Pod-vs-controller matching).

> Caveat on wording: Kyverno's `SigstoreBundle` support exists but the
> documented/testable path is **attestation/provenance-oriented**; we did not
> find a working *raw image-signature* Enforce path for these artifacts.

### Evidence (so the obvious fixes aren't re-tried)
- Tested item-level `repository: ghcr.io/kyverno/signatures` (and IVP
  `attestors.cosign.source`): Kyverno still denied
  `ghcr.io/kyverno/kyverno@sha256:dcd8cf6de2158cd8334fc728f9c4eb521e2c006320a59d69a9b91af87ac8f41c`
  with `.attestors[0].entries[0].keyless: no signatures found`. So it is **not**
  a "signatures live in a different repo" fix.
- Cilium `quay.io/cilium/cilium@sha256:2eb6799…` (digest-pinned) denied at
  Enforce with `no signatures found`, though `cosign verify` against the Cilium
  release workflow identity succeeds ([Cilium image-signature docs]).
- IVP sanity policy emitted no result (plumbing class B).
- Full-Enforce attempt (Steps 44–46) confirmed the live engine denies these real
  images; rolled back.

### Current state
`verify-first-party` = **[Deny]/Fail** (TD-0009 resolved);
`verify-flux-images`, `verify-cilium-images`, `verify-kyverno-images` =
**Audit**. All legacy `verifyImages` rules use `mutateDigest: false`.

### Impact + why High
Cilium is privileged networking/security infrastructure; Kyverno is the
admission/policy control plane — **high blast radius** for a compromised image.
The conditions that would justify *Medium* are **not all met**: Kyverno images
run **tag-only** (not digest-pinned), there is **no alerting on Kyverno audit
failures**, and **no periodic out-of-band digest verification**. Until those
mitigations (esp. Option 0) land, treat as **High**. Audit-only here is a
*temporary risk acceptance*, not a solution.

### Options to close
0. **(Mitigation, not closure) CI / pre-reconciliation digest verification.**
   Before GitOps deploys any Cilium/Kyverno image, `cosign verify` the **exact
   digest** (not tag), assert issuer + workflow subject, fail CI on mismatch,
   store the output as an artifact, and alert if the live cluster digest differs
   from Git. A real control instead of "audit and hope."
1. **Spike [Ratify] for Cilium/Kyverno only** — a non-Kyverno admission verifier
   whose Cosign verifier supports OCI 1.1 referrer signatures via the ORAS
   referrer-store plugin. Accept only if it **denies** unsigned/tampered test
   images, **admits** the real digest-pinned upstream images, enforces the
   intended keyless identities, runs with `failurePolicy: Fail`, and needs no
   broad namespace exceptions. (Adds a second admission stack — adopt
   deliberately.)
2. **Mirror + re-sign** into an internal registry (verify upstream in CI → copy →
   re-sign with our identity in a Kyverno-consumable layout → deploy internal
   digests → enforce against the internal registry). Deterministic closure;
   heavy + ongoing.
3. **Track Kyverno/cosign upstream** referrer/bundle *signature* verification.
   Passive — not the only plan. Trigger: on every Kyverno upgrade run a
   reproducible Enforce-mode conformance test (below). No green test, no closure.
4. **Attestations are supplementary, not equivalent.** Verifying Cilium SBOM or
   Kyverno SLSA provenance (the latter signed by the `slsa-github-generator`
   identity, not Kyverno's release workflow) does **not** close TD-0001 — it is a
   different trust assertion. Only redefining the control from "image-signature
   enforcement" to "supply-chain-metadata enforcement" would change that.

(Sigstore Policy Controller was considered; it also has open bundle/referrer
gaps — [policy-controller #1406] — so it's only worth a spike if Ratify fails.)

### Closure criteria (do NOT close because a policy "looks right")
| Case | Expected |
| --- | --- |
| Real digest-pinned Cilium image | admitted |
| Real digest-pinned Kyverno image | admitted |
| Same ref, missing/invalid signature | denied |
| Wrong GitHub workflow identity | denied |
| Mutable tag without digest | denied, or mutated-then-verified by digest |
| Registry lookup failure | denied (fail-closed), not allowed-open |
| Existing audit report only | **not** sufficient for closure |

### References
[ADR-0010]; `_handoff` Steps 38–53; [cosign #4708]; [Kyverno IVP feedback #14036];
[Cilium image-signature docs]; [Kyverno security / signature repo]; [Ratify Cosign verifier].

---

## TD-0002 — Flux image-signature enforcement deferred

**Opened:** 2026-06-11 · **Status:** Open · **Priority:** Medium ·
**See:** [ADR-0010](decision-records/repo/0010-adopt-kyverno-policy-engine.md)

### Gap
`verify-flux-images` is **Audit**, not Enforce. Flux images verify fine
(legacy `.sig` format, reachable) — this is *not* the TD-0001 format problem.

### Why deferred
Flux uses **tag-only** image refs (`ghcr.io/fluxcd/...:vX`). Enforcing them needs
Kyverno `mutateDigest: true` to resolve tag→digest (Step 52 canary: with
`mutateDigest: false`, Flux is denied `missing digest`; Step 45 showed
`mutateDigest: true` admits). But `mutateDigest: true` requires Enforce, and
**enforcing the GitOps reconciler itself carries a self-heal-deadlock risk**: a
denied Flux controller on recreation can't reconcile — including the fix that
would un-block it. `webhookConfiguration.failurePolicy: Ignore` mitigates
*transient* infra errors (fails open) but not a genuine verification failure.

### Options to close
1. Enforce Flux with `mutateDigest: true` **and** a tested rollback/runbook for
   the deadlock case (e.g. a break-glass path to patch the policy without Flux).
2. Pin Flux images by digest in Git (Renovate-managed) so no `mutateDigest` is
   needed, then Enforce with `mutateDigest: false`.
3. Accept Audit for Flux as a deliberate risk decision (current state).

### References
[ADR-0010]; `_handoff` Steps 45, 52, 53.

---

## TD-0003 — Strict Diataxis quadrant-directory layout not implemented

**Opened:** 2026-07-10 · **Status:** Open · **Priority:** Medium ·
**See:** [ADR-0002](decision-records/org/0002-adopt-diataxis-documentation-framework.md);
[Docs index](README.md)

### Gap
The repository organizes current non-ADR docs by Diataxis purpose through
`docs/README.md`, but it does not yet implement ADR-0002's mandatory
`docs/{tutorials,how-to,reference,explanation}/` skeleton. Runbooks remain in
`docs/runbooks/` rather than `docs/how-to/`.

### Why deferred
Moving the runbooks now would require updating the ADR-0022 byte-match-guarded
Longhorn cluster-manifest comments that reference `docs/runbooks/dr-stage1-backup.md`
in both `addons/longhorn/values.yaml` and
`clusters/talos-cluster/apps/longhorn/release/helmrelease.yaml`. That manifest
touch is disproportionate for the current docs-only reconciliation, so this
cycle fixes the false compliance claim and records the layout gap instead.

### Options to close
1. Create the four required quadrant directories
   `docs/tutorials/`, `docs/how-to/`, `docs/reference/`, and
   `docs/explanation/`, using `.gitkeep` for empty quadrants.
2. Move `docs/runbooks/*` to `docs/how-to/`.
3. Move lookup-oriented docs to `docs/reference/`.
4. Update all references, including the two lockstep Longhorn cluster-manifest
   comments that currently point at `docs/runbooks/dr-stage1-backup.md`.
5. Update `docs/README.md` so it indexes the strict layout instead of this
   temporary purpose classification.

### References
[ADR-0002]; [Docs index](README.md).

---

## TD-0004 — Org-ADR drift gate neutralized pending allowlist restoration

**Opened:** 2026-07-11 · **Status:** Resolved · **Priority:** High ·
**Resolved:** 2026-07-12 · **See:** P0.1 (owner console Actions allowlist item);
[Org ADR Sync workflow]; [Workflow-health sweep].

### Resolution
P0.1 allowlisted `NWarila/drift-gate`, and dispatch run 29153562800
proved the `org-adr / verify` check posts. PR-time triggering is restored in
`org-adr-sync.yaml` with `pull_request` on `branches: [main]` plus concurrency.
Claude live verification on 2026-07-12 confirmed the gate GREEN on the restoring
PR and proven fails-closed on a deliberate drift PR (see `_handoff/PLAN.md` §10).
The `org-adr-sync.yaml` workflow-health exception requirement is already
satisfied because `scripts/check-workflow-health.py` has no such exception.

### Gap
The PR-time org-ADR drift gate is non-functional. The workflow calls
`NWarila/drift-gate`, but the repository's Actions policy uses
`allowed_actions: selected` and the action is not allowlisted. GitHub rejects
each run before starting any jobs, so the intended `org-adr / verify` check is
never posted.

### Current state (at open time)
`org-adr-sync.yaml` was neutralized, not fixed. Its automatic `pull_request` and
`schedule` triggers had been removed, leaving `workflow_dispatch` only. This
stopped adding failures on every PR and weekly schedule but did not restore
PR-time enforcement. The real drift-gate step remained in place so a manual run
would exercise the intended gate once P0.1 restored the allowlist.

### Options to close
1. Complete P0.1 by allowlisting `NWarila/drift-gate` under the repository's
   selected Actions policy, then restore PR-time triggering after a green run
   proves the `org-adr / verify` check posts.
2. Vendor an inline `checkout` + Python replacement in this repository that owns
   the manifest-drift logic, then restore PR-time triggering around that in-repo
   gate.

### Closure criteria
- PRs run an org-ADR drift gate automatically.
- The gate fails closed on manifest drift and posts the `org-adr / verify`
  check.
- The `org-adr-sync.yaml` workflow-health exception can be removed without the
  sweep failing as stale or non-excepted red.

### References
P0.1; [Org ADR Sync workflow]; [Workflow-health sweep].

---

## TD-0005 — Stage-1 offsite/offline copy remains future work

**Opened:** 2026-07-11 · **Status:** Open · **Priority:** Medium ·
**See:** [ADR-0021]; [DR Stage 1 limitations].

### Gap
Stage-1 Longhorn backups currently provide accepted LOCAL operational recovery on
the Synology NAS, but the offsite/offline copy required to complete the
3-2-1-1-0 posture remains future work.

### Current state and mitigation
This is an accepted residual. Stage-1 is accepted LOCAL operational recovery
today: the current target is an always-on Synology appliance with RAID6+Btrfs, a
dedicated NFS share, and NAS-side immutable snapshots; it replaces the retired
session-bound WSL target and is the operational recovery layer today. The
remaining gap is the maturation path to an offsite or offline copy after the
on-site target is stable and retention is proven.

### Closure criteria
- A documented offsite or offline copy path exists for the Stage-1 backup data.
- Retention, access control, and restore procedure for that copy are documented.
- A restore or integrity-validation drill proves the offsite/offline copy is usable
  without relying on the local NAS as the only backup target.

### References
[ADR-0021]; [DR Stage 1 limitations].

---

## TD-0006 — Backup-target transport and share-at-rest crypto remain accepted residuals

**Opened:** 2026-07-11 · **Status:** Open · **Priority:** Low ·
**See:** [ADR-0021]; [DR Stage 1 limitations].

### Gap
The Stage-1 backup target uses unencrypted NFS transport (AUTH_SYS, no TLS/krb5p),
and the Synology share is not encrypted at rest.

### Current state and mitigation
This is an accepted residual for the current Vault-Raft backup payload. The backup
path is mitigated by the isolated storage VLAN, per-host NFS export scoping, and
the barrier-encrypted Vault-Raft payload inside the Longhorn backup. The escalation
trigger is explicit: revisit this posture before backing up non-barrier-encrypted
sensitive PVs here.

### Closure criteria
- Backup transport uses authenticated encryption or an approved replacement with
  equivalent confidentiality and integrity properties.
- The backup share is encrypted at rest, or an ADR records why the replacement
  posture is sufficient for all payload classes stored there.
- Before any non-barrier-encrypted sensitive PV is backed up here, this entry is
  revisited and either closed by controls above or updated with explicit risk
  acceptance.

### References
[ADR-0021]; [DR Stage 1 limitations].

---

## TD-0007 — NAS administrative and appliance isolation trust boundary accepted residuals

**Opened:** 2026-07-11 · **Status:** Open · **Priority:** Low ·
**See:** [ADR-0021]; [DR Stage 1 limitations].

### Gap
Two accepted residuals remain in the NAS administrative and isolation boundary:
- DSM administrative residual: a DSM administrator can delete snapshots outside the
  7-day WORM lock.
- Appliance isolation residual: the Synology appliance is shared with unrelated
  business backups and is not a dedicated backup host.

### Current state and mitigation
The DSM administrative residual is mitigated by the 7-day immutable-snapshot lock,
and the setup DSM-admin credentials are rotated and never stored in-cluster. The
appliance isolation residual is mitigated by using a dedicated `longhorn-backup`
share, a 100 GB quota, and per-host NFS export scoping for the Talos nodes.

### Closure criteria
- DSM administrative residual: snapshot retention has a control that prevents or
  independently detects privileged deletion outside the current 7-day WORM lock.
- Appliance isolation residual: the Stage-1 backup target runs on dedicated backup
  infrastructure, or an ADR explicitly accepts the shared-appliance posture with
  reviewed compensating controls.

### References
[ADR-0021]; [DR Stage 1 limitations].

---

## TD-0008 — Selector-bound Vault auth roles cannot be operator-reconciled

**Opened:** 2026-07-15 · **Status:** Open · **Priority:** Medium ·
**See:** CP-4 design §S4b (`_handoff/CP4-VAULT-CONFIG-RECONCILER-DESIGN.md`); PR #311 (S4a).

### Gap
CP-4 S4a made the managed Vault config Flux-reconciled via the redhat-cop
vault-config-operator, but adopted only the **6 policies + 2 static-namespace
roles**. The other **3 k8s-auth roles** — `tenant`, `vso-org-pull-hwg`,
`vso-org-pull-nwp` — bind tenant namespaces through Vault's
`bound_service_account_namespace_selector` (a **login-time**, Vault-side label
match). They remain **capture-only** (`apps/vault/vault-config/auth/kubernetes/roles/*.json`),
re-applied by a hand-typed `vault write` on rebuild — a residual zero-manual
([[zero_manual_north_star]]) violation scoped to exactly these 3 objects.

### Root cause (precise)
`redhat-cop/vault-config-operator` `KubernetesAuthEngineRole` **v0.8.49 cannot
express** `bound_service_account_namespace_selector`. Its nearest field,
`spec.targetNamespaces.targetNamespaceSelector`, resolves the selector **in
Kubernetes at reconcile time** (the controller watches Namespaces) and writes a
**static** `bound_service_account_namespaces` list. Because a Vault role write is
a full-document upsert, adopting these roles as-is would **silently replace the
live login-time selector binding with a reconcile-time static list** — a
different semantics, not an adoption.

### Why deferred (owner decision 2026-07-15)
- Accepting the selector→static-list rewrite (below, option 2) trades a
  Vault-native login-time binding for one that depends on **operator liveness**
  (a brand-new tenant namespace can't log in until the operator reconciles the
  list) and **lags de-label revocation** if the operator is down — a reliability
  regression the owner declined ([[feedback_reliability_zero_compromises]]).
- The clean fix is an **upstream patch** to the operator, but the owner will not
  self-sign a forked operator image (*"we are NOT going to re-sign someone
  else's items"*), and an upstream contribution has an indefinite merge timeline.
- So: **book the gap as real debt now; explore the upstream fix later.**

### Current state + impact (why Medium, not High)
**No functional impact today** — the 3 roles are applied and working live; VSO
tenant secret delivery is healthy. The debt is that these 3 objects are (a) not
rebuild-reproducible without a manual `vault write`, and (b) drift to them is
invisible (nothing reconciles them). Bounded: they are tenant/org-pull **auth
bindings**, not policy **content** (a compromised git commit cannot escalate
through them), and the manual rebuild step is documented DR material. Not Low
because it is a live, ongoing zero-manual violation on the tenant auth path.

### Options to close
1. **(Explore — owner-preferred direction) Upstream passthrough patch.** Add
   `bound_service_account_namespace_selector` passthrough to the operator's
   `VRole` / `toMap()` / CRD schema (+ validation + tests) in
   `redhat-cop/vault-config-operator`; once it ships in an official release,
   adopt the 3 roles byte-identically (verify with
   `scripts/vault-config/verify-adoption-parity.py`). **No self-signed fork
   image** — consume an upstream release only.
2. Accept the selector→static-list semantics with a documented reliability
   residual (operator-liveness-dependent new-tenant login). **Rejected**
   2026-07-15.
3. Keep the 3 roles out-of-band as a permanent owned exception (bootstrap-class
   capture, like the `vault-admin` break-glass policy) rather than debt —
   fallback if the upstream path never moves.

### Closure criteria
- The 3 selector roles are Flux-reconciled with their live
  `bound_service_account_namespace_selector` binding preserved **byte-identically**
  (parity-verified), with **no** manual `vault write` on rebuild and **no** new
  operator-liveness dependency introduced for tenant login.

### References
CP-4 design §S4b; [[vault_config_reconciler_oss_root_equiv]]; PR #311;
`clusters/talos-cluster/apps/vault/vault-config/README.md` (S4b section).

---

## TD-0009 — First-party image admission enforcement was temporarily non-blocking

**Opened:** 2026-07-19 · **Status:** Resolved · **Priority:** High ·
**Resolved:** 2026-07-19 ·
**See:** [ADR-0027].

### Resolution
This PR flips `ImageValidatingPolicy/verify-first-party` and the guard constants
to `validationActions: [Deny]` plus `failurePolicy: Fail`. The live Audit canary
proved the merged policy against real first-party images: PolicyReports were
all-pass with zero non-pass results and zero rule errors. The canary expiry
constant remains in the guard, but it is inert while the IVP is at steady-state
`[Deny]`/`Fail`.

### Gap
At open time, first-party image signatures were verified by one merged
`ImageValidatingPolicy/verify-first-party` at `validationActions: [Audit]` and
`failurePolicy: Ignore`. That was deliberate canary telemetry, not blocking
admission: an unsigned, wrong-identity, or stale-pin first-party image would
have been reported rather than denied until this PR landed.

### Why deferred
Kyverno v1.18.2 exposed two defects in the previous three-IVP shape: IVP
annotation clobber between policy outcome entries, and autogen slot collision
under the global generated-policy names. The merge to one IVP removes that
multi-policy collision class, but it needed a live non-blocking canary because
Kyverno's policy-validation webhook can accept CEL that later fails at runtime.
The canary proved the merged CEL, offline Sigstore pins, and shared `ghcr-pull`
credential path against real first-party images before this PR restored
fail-closed admission.

### Current state + mitigation
CI pins the single-IVP shape, nested IVP spec fields, Sigstore offline pins,
first-party CEL, credentials, and the `[Deny]`/`Fail` posture. The guard also
carries `IVP_CANARY_EXPIRES = "2026-08-01"` so any future forgotten canary turns
CI red instead of remaining non-blocking silently.

### Closure evidence
- `ImageValidatingPolicy/verify-first-party` and the guard constants are at
  `validationActions: [Deny]` plus `failurePolicy: Fail`.
- The canary expiry remains inert after the steady-state `[Deny]`/`Fail` posture
  is reached.

### References
[ADR-0027]; `scripts/check-image-signature-enforcement.py`.

---

## TD-0010 — kube-system remains outside the declared PSA floor

**Opened:** 2026-07-19 · **Status:** Open · **Priority:** High

### Gap
`kube-system` carries no Pod Security Admission labels live, is Talos-managed,
and is not declared as a Namespace manifest in this repository. That leaves a
real hole in the PSA floor: anything that can create pods there is not constrained
by namespace-level PSA.

### Why deferred
The namespace holds genuinely privileged Talos/Kubernetes system workloads, and
the running-pod PSA audit found restricted violations there. This repository
therefore cannot safely adopt `kube-system` as restricted based on the current
evidence, and Talos owns the namespace lifecycle rather than this GitOps tree.

### Current state and impact
This is not treated as a non-issue. The rest of the declared namespace surface is
guarded in source, and `longhorn-system` is an explicit privileged exemption, but
`kube-system` remains an unlabelled live namespace outside that declared control.
The blast radius is bounded to actors that can create or mutate workloads in
`kube-system`, but that is still a high-value system namespace.

### Closure criteria
- A reviewed Talos-compatible mechanism declares PSA labels for `kube-system`
  reproducibly, without Flux fighting Talos-managed lifecycle.
- Either the system workloads are proven restricted-compliant and the namespace
  can be labelled restricted, or `kube-system` is recorded as an explicit
  privileged PSA exemption with the full six-label set and a written
  justification.
- CI or an operational drift check proves the live `kube-system` label state does
  not silently regress after upgrades or recovery operations.

---

## TD-0011 — Tenant image pulls use an org-wide classic PAT that cannot be repo-scoped

**Opened:** 2026-07-19 · **Status:** Open · **Priority:** High · **Descoped from the MVP gate by the owner on 2026-07-19 (was CP-3).**

### Gap
Tenant workloads pull private first-party images using `ghcr-pull`, delivered by VSO from
`secret/data/platform/org-pull/<org>/ghcr-pull`. That credential is a **classic** GitHub
Personal Access Token carrying `read:packages`.

Classic PAT scopes are **account-wide**: `read:packages` grants read on *every* package the
owning account can read. **There is no mechanism to narrow a classic PAT to a single
repository.** The credential is therefore structurally org-wide, and it is mounted into a
tenant pod.

**Blast radius:** a compromised tenant pod can read every private package in the org, not
merely the one image that tenant runs.

**Confirmed not at risk:** both PATs are `read:packages` only (owner-verified), so a
compromised tenant cannot *push* images. Both carry **no expiration date**, so a leaked
token remains valid indefinitely.

**Trajectory:** the owner intends to publish private containers under the `nwarila` org as
well (the `nwarila-talos-ghcr-pull` PAT is pre-provisioned for exactly that and is
intentionally retained). The exposure therefore grows as private images spread across both
orgs — this does not stay a single-tenant concern.

### Why deferred
It is a blast-radius reduction, not a missing control: image pulls are authenticated today,
signatures are enforced fail-closed at admission (ADR-0027), and no unauthorised pull path
exists. It does not gate the MVP contract, and the owner descoped it accordingly.

### What closes it
Per-tenant scoped, automatically-rotating pull credentials. Two viable routes:

1. **Preferred — GitHub App with `packages: read`.** `scripts`/the source-rotator minter
   already issues installation tokens scoped to specific repositories
   (`{"repositories":[repo]}`); it currently requests only `{"contents":"read"}` because no
   App in the org holds `packages`. Granting one App `packages: read` lets the existing
   machinery mint a per-tenant, per-repo, short-lived credential — removing both the
   org-wide scope and the never-expiring property in one change, with no new manual artefact.
2. **Fallback — a fine-grained PAT per tenant**, scoped to that repository with
   Packages: read. Works with no App change, but is a hand-made artefact per tenant with no
   auto-rotation, which re-creates the toil the source-rotator exists to remove and scales
   poorly as private images spread.

Route 1 is consistent with the zero-manual doctrine; route 2 is a stopgap.

---

## TD-0012 — Source-minter Vault policies grant a CROSS-ORG write on the tenant source-auth leaf

**Opened:** 2026-07-20 · **Status:** Open · **Priority:** Medium

### Gap
Every per-org source minter holds
`path "secret/data/+/provisioned/source-auth" { capabilities = ["create", "update"] }`.
The `+` matches **any single path segment**, so `source-minter-nwp` can write the
`source-auth` leaf of **any** tenant namespace — including `hwg-*` — and vice versa. The
org suffix in the role name implies an isolation the policy does not actually enforce.

While only one organization existed the wildcard was effectively self-scoped and inert.
Onboarding `nwp` (2026-07-20) turned it into a real cross-org write capability. It was
found by an independent adversarial audit of that change, not by a guard.

### Why deferred
Vault ACL cannot express the scope we want. `*` is legal only as the **final** character of
a path and `+` matches exactly one **whole** segment, so neither `secret/data/nwp-*/provisioned/source-auth`
nor `secret/data/nwp-+/provisioned/source-auth` is a valid narrowing. The only two
expressible shapes are:

| Option | Scope | Cost |
|---|---|---|
| `secret/data/+/provisioned/source-auth` (today) | narrow leaf, **any** org | cross-org write |
| `secret/data/<prefix>-*` | org-scoped | widens to the **entire** tenant subtree, including tenant state |

Neither is strictly better, so this is a deliberate trade rather than an oversight.

### Two triggers, not one
This was first written as a *compromised-holder* residual. An adversarial audit established a
second, purely **accidental** trigger that needs no compromise at all:

1. **Compromised holder.** Any principal holding a `source-minter-*` policy can write any
   tenant's `source-auth` leaf.
2. **Misconfigured `ORG_LABEL`.** That variable affects neither Vault authentication nor the
   App-key read — it only selects which tenant namespaces to mint for. An onboarding
   copy-paste that leaves the previous org's `ORG_LABEL` in a new CronJob makes org A's
   minter select org B's tenants. The mint normally fails, but **only contingently**: it
   sends a *bare* repository name (a `nwarila.io/deploy-repo` label value cannot contain a
   slash), which GitHub resolves inside the minter's own installation. If a same-named
   repository exists there, the mint **succeeds** and the token is written cross-org. The job
   logs `OK <namespace> -> <repo> (cas N)` — silent, not loud.

### Current state and impact
The Git repository URL lives in the tenant's `GitRepository` CR, **not** in this secret, so an
overwrite does not redirect a tenant's fetch. But the impact is **not** limited to denial of
service, and an earlier version of this entry was wrong to say so:

- **Denial of service** — the victim tenant's `source-auth` is replaced with a token that does
  not authorize its repository, so its Flux source stops reconciling.
- **Cross-org credential placement** — the writing org's token is deposited **inside the
  victim org's tenant namespace**, where that tenant's VSO syncs it into a Secret and its
  workloads can read it. A credential belonging to org A becomes readable by org B. That is a
  disclosure, not merely an outage.

Two facts bound both impacts, and are recorded so this entry is not read as worse than it is:

- **The deposited credential is narrow and short-lived.** It is a `contents:read` GitHub App
  installation token scoped to a SINGLE repository, and such tokens expire in about an hour,
  so the disclosure window is bounded even if nobody notices.
- **The denial of service is self-healing, not terminal.** The legitimate rotator reruns on
  its own schedule (hwg `*/45`, nwp `10,55`), so a clobbered leaf is rewritten within roughly
  45 minutes. The realistic symptom is a tenant whose source fetch FLAPS, not one that stops
  permanently — which is also why it could persist unnoticed.

It stays **Medium** rather than High because reaching it requires either a compromised minter
or a misconfiguration *plus* a cross-org repository name collision, and because no
`nwarila-platform` tenant exists yet.

⚠️ **Point-in-time, and it will rot:** at the time of writing the only bare-name collision
between the two org families is `.github`, which is not a deploy repository. That is a fact
about today's repository inventory, not a property of the design — adding repositories can
create a collision at any time, silently. Do not treat it as a standing mitigation.

One control is weaker than it looks: the minter *sends* a kv-v2 check-and-set on every write
(`configmap.yaml`), but the ACL grants plain `create`/`update`. CAS is therefore a property of
**our client**, not an enforced constraint — a compromised principal holding this policy can
omit `cas` and clobber unconditionally. Enforcing it means setting `cas_required` — either
mount-wide (affecting every writer) or per-secret via that secret's kv-v2 metadata. Neither
closes this gap on its own: the policy already grants `secret/metadata/+/provisioned/source-auth`
read, which hands a deliberate attacker the current version number needed to satisfy CAS
anyway. CAS is a concurrency control, not an authorization control.

### What closes it
Any of:
1. A Vault release whose ACL syntax can express an intra-segment prefix together with a
   deeper suffix.
2. Restructuring tenant KV so each org's tenants sit under an org-owned parent segment
   (e.g. `secret/data/tenants/<prefix>/<tenant>/provisioned/source-auth`), after which
   `secret/data/tenants/nwp/+/provisioned/source-auth` expresses the intent exactly. This
   is the preferred route; it is a KV-layout migration touching VSO consumers and the
   tenant template.
3. Replacing the shared-wildcard grant with per-tenant policy generation at onboarding,
   which reintroduces per-tenant Vault toil and is contrary to the zero-manual doctrine.

Option 2 is now the clear preference: an org-parented KV layout makes the cross-org write
impossible *regardless of `ORG_LABEL`*, closing the accidental trigger structurally rather
than relying on repository names never colliding.

**Cheap partial mitigation, not yet applied:** the minter could assert that each selected
tenant namespace carries its own org prefix (derivable from its `VAULT_ROLE`) before minting,
which would kill the accidental trigger in a few lines without touching the KV layout. It does
nothing for the compromised-holder trigger, so it complements rather than replaces option 2.

**Both org policies must change together.** Tightening one side leaves the hole open in the
other direction.

### References
- `clusters/talos-cluster/apps/vault/vault-config/managed/policy-source-minter-nwp.yaml`
- `clusters/talos-cluster/apps/vault/vault-config/managed/policy-source-minter-hwg.yaml`
- [Onboard a new organization](runbooks/onboard-organization.md)

---

[ADR-0010]: decision-records/repo/0010-adopt-kyverno-policy-engine.md
[ADR-0002]: decision-records/org/0002-adopt-diataxis-documentation-framework.md
[ADR-0021]: decision-records/repo/0021-synology-nfs-backup-target-for-longhorn.md
[ADR-0027]: decision-records/repo/0027-fail-closed-first-party-image-admission.md
[DR Stage 1 limitations]: runbooks/dr-stage1-backup.md#limitations-and-intent
[Docs index](README.md): README.md
[Org ADR Sync workflow]: ../.github/workflows/org-adr-sync.yaml
[Workflow-health sweep]: ../scripts/check-workflow-health.py
[cosign #4708]: https://github.com/sigstore/cosign/issues/4708
[Kyverno IVP feedback #14036]: https://github.com/kyverno/kyverno/discussions/14036
[Cilium image-signature docs]: https://docs.cilium.io/en/stable/configuration/verify-image-signatures/
[Kyverno security / signature repo]: https://kyverno.io/docs/guides/security/
[Ratify]: https://ratify.dev/docs/plugins/verifier/cosign/
[Ratify Cosign verifier]: https://ratify.dev/docs/plugins/verifier/cosign/
[policy-controller #1406]: https://github.com/sigstore/policy-controller/issues/1406
