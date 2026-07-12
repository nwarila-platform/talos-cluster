# ADR-0006: Digest-pin the image and verify its signature on-cluster

| Field          | Value                                   |
| -------------- | --------------------------------------- |
| Status         | Accepted                                |
| Date           | 2026-06-01                              |
| Authors        | Nick Warila (@NWarila)                  |
| Decision-maker | Nick Warila (sole portfolio maintainer) |
| Consulted      | None.                                   |
| Informed       | None.                                   |
| Reversibility  | High                                    |
| Review-by      | N/A (Accepted)                          |

## TL;DR

All manifests reference the Vault image by **`@sha256:` digest**, never by tag.
The cluster verifies the image's keyless Cosign signature via Kyverno
(**Audit** first). No secret material — including the GHCR pull credential —
is committed.

## Context and Problem Statement

`ubi9-hashicorp-vault` publishes a signed, attested image. The image package
must remain public so deploy-* repositories can reconcile without per-app
registry credentials. Tag-based references would undermine reproducibility and
verification.

## Decision Drivers

- Reproducible, tamper-evident deployments (digest addressing).
- Provenance enforcement (the image is signed; verify it).
- Talos has no ambient registry credentials, so public platform images avoid
  per-app pull-secret plumbing.
- Deny-all `.gitignore` forbids committing secrets.

## Decision Outcome

**Chosen.**

- **Digest pin:** Kustomize `images:` maps the image to
  `digest: sha256:f4c4422b5a8ec5a56db67b937b429e655e5fd73e2c7c9a308e1636520fb5f244`
  (the verified `main` build). `scripts/check-image-digest-sync.py` in the
  validation workflow fails on explicit `:tag` refs for first-party images and
  on duplicate concrete digest refs for the same image name that drift apart.
- **Package visibility:** the GHCR image package is public. Do not add registry
  pull secrets for this image; if pulls fail with `ImagePullBackOff`, fix GHCR
  package visibility.
- **Signature verification (Kyverno):** the cluster-side policy in
  `talos-cluster` uses keyless Cosign with
  issuer `https://token.actions.githubusercontent.com` and subject regexp
  `^https://github\.com/nwarila-platform/ubi9-hashicorp-vault/\.github/workflows/publish-image\.yaml@refs/(heads/main|tags/v.*)$`.
  Start in **Audit**; move to Enforce only after PolicyReports show consistent
  signature verification passes.

## Confirmation

`cosign verify` / `gh attestation verify` of the pinned digest succeed; a
Kyverno PolicyReport records a pass for the Vault pods; the validation workflow
runs `scripts/check-image-digest-sync.py`, which rejects tag-pinned first-party
images and duplicate image-name digest drift.

## Consequences

### Positive
- Tamper-evident, provenance-checked deployments.

### Negative
- Public image visibility exposes package metadata and layers for inspection;
  the image must never contain secrets or private artifacts.
- Digest must be bumped deliberately on image updates (Renovate can automate).

## Related ADRs

- [ADR-0001](0001-use-kustomize-not-helm-chart.md) — Kustomize `images:` pinning.
