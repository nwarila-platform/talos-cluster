# Technical Debt Register

Known, deliberately-deferred gaps. Each entry records the gap, why it was
deferred, its impact, and the concrete options to close it. Decisions live in
the ADRs; this register tracks the *debt* those decisions leave behind.

| ID | Title | Status | Priority |
| --- | --- | --- | --- |
| TD-0001 | Cilium + Kyverno images cannot be signature-enforced at admission | Open | **High** |
| TD-0002 | Flux image-signature enforcement deferred | Open | Medium |

---

## TD-0001 — Cilium + Kyverno images cannot be signature-enforced at admission

**Opened:** 2026-06-11 · **Status:** Open · **Priority:** High ·
**See:** [ADR-0010](decision-records/repo/0010-adopt-kyverno-policy-engine.md)

### Gap
Cosign image-signature verification is **enforced** for `ghcr.io/nwarila-platform/*`
(org images). **Cilium** (`quay.io/cilium/*`) and **Kyverno** (`ghcr.io/kyverno/*`)
are **Audit-only** — an unsigned/tampered Cilium or Kyverno image is *reported*
but not *blocked* at admission. (Flux is a separate item — see TD-0002.)

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
`verify-nwarila-platform-images` = **Enforce**; `verify-flux-images`,
`verify-cilium-images`, `verify-kyverno-images` = **Audit**. All `mutateDigest: false`.

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

[ADR-0010]: decision-records/repo/0010-adopt-kyverno-policy-engine.md
[cosign #4708]: https://github.com/sigstore/cosign/issues/4708
[Kyverno IVP feedback #14036]: https://github.com/kyverno/kyverno/discussions/14036
[Cilium image-signature docs]: https://docs.cilium.io/en/stable/configuration/verify-image-signatures/
[Kyverno security / signature repo]: https://kyverno.io/docs/guides/security/
[Ratify]: https://ratify.dev/docs/plugins/verifier/cosign/
[Ratify Cosign verifier]: https://ratify.dev/docs/plugins/verifier/cosign/
[policy-controller #1406]: https://github.com/sigstore/policy-controller/issues/1406
