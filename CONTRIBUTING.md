# Contributing

Thanks for looking. This repository documents a real, running Talos Kubernetes platform and is
published for **transparency and as a portfolio reference** — not as a collaborative project actively
soliciting external contributions. That context shapes how contributions are handled.

## Issues and discussion

Questions, factual corrections, and observations are welcome via **GitHub Issues**. A well-reasoned
"this claim doesn't match the code" issue is especially valued — the repository's stated standard is
*zero claims it cannot prove*, so pointing out a gap between a doc and the manifests is a real
contribution.

## Pull requests

Because every change flows through GitOps with signed commits and owner review, external pull requests
are unlikely to be merged directly into `main`. Small, well-scoped fixes (typos, broken links,
factual corrections) are still appreciated as a concrete basis for discussion.

## How this repository works

- **GitOps is the source of truth.** Flux reconciles everything under `clusters/talos-cluster/`;
  changes land by merging to `main`, not by touching the cluster directly.
- **Everything is validated in CI.** See `.github/workflows/` — configs are rendered and validated,
  secrets are scanned, and dedicated guards enforce the security boundaries. A change that fails a
  guard is expected to fail; the guard is the reviewer.
- **Commits are signed** and messages describe *why*, not just *what*.
- **Secrets never land in plaintext.** SOPS with age encrypts secret payloads in git; a deny-all
  `.gitignore` allowlists tracked files explicitly.
- **Architecture decisions are recorded** under `docs/decision-records/`. Non-trivial changes should
  reference or add an ADR.

## Ground rules

- Do not add real secrets, tokens, or private keys in plaintext.
- Keep documentation truthful — if a control is audit-only, say so; do not overclaim enforcement.
- Match the surrounding style and keep changes minimal and reviewable.
