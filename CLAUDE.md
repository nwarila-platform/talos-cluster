@AGENTS.md

# TDNHQ-TALCL01 - Talos Kubernetes Cluster

The imported `AGENTS.md` file is the authoritative operating loop for cross-LLM
audit, plan, adversarial review, implementation, and verification. This file
only adds Claude-facing quick context for this repository.

## Overview
Production TalosOS Kubernetes cluster for the TDNHQ site.

## Architecture
- 3x Control Plane nodes (`cp1`, `cp2`, `cp3` — asset names TDNHQ-TLOMGT01/02/03) with shared VIP at 10.69.112.62
- 3x Worker nodes (`w1`, `w2`, `w3` — asset names TDNHQ-TLOWRK01/02/03)
- Cilium CNI (replaces kube-proxy), Flux GitOps, Gateway API, Kyverno, metrics-server, Longhorn, SOPS/age encrypted Kubernetes secrets
- All machine configs managed as code via Talos config patches
- Secrets stored in AWS S3 (locally mirrored in `.s3/`)

## Key Conventions
- **NEVER commit secrets to git** - `.s3/` is gitignored
- Version pinning lives in `cluster/config.env` - single source of truth
- Node-specific configs are Talos strategic merge patches in `cluster/patches/`
- Hostnames use Talos 1.12+ `HostnameConfig` (set via sed in generate.sh, not machine.network.hostname). Short names (`cp1`…`w3`) match the live cluster — see `docs/decision-records/repo/0002-use-short-talos-hostnames.md`.
- Install disk is `/dev/nvme0n1` on every node; declared per-node so future hardware variation is explicit.
- This repository is the cluster's declarative source of truth — see `docs/decision-records/repo/0003-repo-as-cluster-source-of-truth.md`. Out-of-band changes require a back-fill PR within 7 days.
- All automation flows through the Makefile which delegates to `scripts/`
- CI/CD workflows validate configs on PR, deploy via manual trigger
- On Windows/Git Bash, use `MSYS_NO_PATHCONV=1` before Helm commands with Unix paths

## Common Commands
```
make generate       # Generate machine configs from patches + secrets
make validate       # Validate generated configs
make apply          # Apply configs to all nodes
make apply-insecure # Apply configs before PKI is established
make bootstrap      # Bootstrap cluster (run ONCE on initial setup)
make health         # Run cluster health checks
make upgrade        # Rolling upgrade of Talos on all nodes
make s3-push        # Push local secrets to AWS S3
make s3-pull        # Pull secrets from AWS S3
```

## File Layout
- `cluster/config.env` - Cluster configuration and version pins
- `cluster/patches/` - Talos machine config patches (safe for git)
- `addons/` - Helm values and K8s manifests for cluster addons
- `scripts/` - Automation scripts sourced by Makefile
- `.s3/` - Local S3 mirror for secrets (gitignored)
- `.github/workflows/` - CI/CD pipelines
- `systems` - Node inventory cross-reference (Talos hostname ↔ asset name ↔ IP)
