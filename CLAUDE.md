@AGENTS.md

# TDNHQ-TALCL01 - Talos Kubernetes Cluster

The imported `AGENTS.md` file is the authoritative operating loop for cross-LLM
audit, plan, adversarial review, implementation, and verification. This file
only adds Claude-facing quick context for this repository.

## Overview
Production TalosOS Kubernetes cluster for the TDNHQ site.

## Architecture
- 2x Control Plane nodes (TDNHQ-TLOMGT01/02) with shared VIP at 10.69.112.62
- 2x Worker nodes (TDNHQ-TLOWRK01/02)
- Cilium CNI (replaces kube-proxy), ingress-nginx, metrics-server, local-path-provisioner
- All machine configs managed as code via Talos config patches
- Secrets stored in AWS S3 (locally mirrored in `.s3/`)

## Key Conventions
- **NEVER commit secrets to git** - `.s3/` is gitignored
- Version pinning lives in `cluster/config.env` - single source of truth
- Node-specific configs are Talos strategic merge patches in `cluster/patches/`
- Hostnames use Talos 1.12+ `HostnameConfig` (set via sed in generate.sh, not machine.network.hostname)
- Install disks differ per node - set in individual patch files
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
- `systems` - Original node IP inventory reference
