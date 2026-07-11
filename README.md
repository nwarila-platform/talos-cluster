# TDNHQ-TALCL01

## Table of Contents

1. [What Is This?](#what-is-this)
2. [How It Works (The Big Picture)](#how-it-works-the-big-picture)
3. [Our Specific Cluster](#our-specific-cluster)
4. [What Software Is Installed](#what-software-is-installed)
5. [Current Architecture](#current-architecture)
6. [Repository Layout](#repository-layout)
7. [What You Need Before Starting](#what-you-need-before-starting)
8. [Setup From Scratch (Full Walkthrough)](#setup-from-scratch-full-walkthrough)
   - [Step 1: Install the Tools](#step-1-install-the-tools)
   - [Step 2: Clone This Repository](#step-2-clone-this-repository)
   - [Step 3: Generate Machine Configs](#step-3-generate-machine-configs)
   - [Step 4: Validate the Configs](#step-4-validate-the-configs)
   - [Step 5: Boot the Talos Nodes](#step-5-boot-the-talos-nodes)
   - [Step 6: Apply Configs to the Nodes](#step-6-apply-configs-to-the-nodes)
   - [Step 7: Bootstrap the Cluster](#step-7-bootstrap-the-cluster)
   - [Step 8: Install Cilium (Networking)](#step-8-install-cilium-networking)
   - [Step 9: Approve Kubelet Certificates](#step-9-approve-kubelet-certificates)
   - [Step 10: Reconcile GitOps Addons](#step-10-reconcile-gitops-addons)
   - [Step 11: Verify Everything Works](#step-11-verify-everything-works)
   - [Step 12: Back Up Your Secrets](#step-12-back-up-your-secrets)
9. [Day-to-Day Operations](#day-to-day-operations)
   - [Checking Cluster Health](#checking-cluster-health)
   - [Changing a Cluster Setting](#changing-a-cluster-setting)
   - [Upgrading Talos to a New Version](#upgrading-talos-to-a-new-version)
   - [Adding a New Worker Node](#adding-a-new-worker-node)
   - [Removing a Worker Node](#removing-a-worker-node)
   - [Recovering Secrets on a New Machine](#recovering-secrets-on-a-new-machine)
   - [Deploying Your Own Application](#deploying-your-own-application)
10. [CI/CD (Automated Pipelines)](#cicd-automated-pipelines)
11. [Security](#security)
12. [Troubleshooting](#troubleshooting)
13. [Windows / Git Bash Notes](#windows--git-bash-notes)
14. [Quick Reference (All Commands)](#quick-reference-all-commands)
15. [Glossary](#glossary)

---

## What Is This?

This repository contains everything needed to deploy, manage, and operate a **Kubernetes cluster** running on **TalosOS**.

Here's what those terms mean in plain language:

- **Kubernetes** is a system that runs applications inside lightweight packages called "containers." Instead of installing software directly on a computer, you put it in a container that can run anywhere. Kubernetes manages many of these containers across multiple computers, making sure they stay running, can handle traffic, and recover from failures.

- **TalosOS** is the operating system installed on each computer (called a "node") in the cluster. Unlike Windows or a regular Linux install, TalosOS is *immutable* — you cannot SSH into it, you cannot install software on it, and you cannot change files on it. It is managed entirely through an API (a programmatic interface). This makes it extremely secure and consistent. If a node has a problem, you don't debug it — you replace it.

- **A cluster** is a group of computers working together as one. Ours has 6 physical machines (nodes).

This repository is the rebuild source for the cluster. Machine-readable node endpoints, role partition, VIP, bootstrap node, and version pins live in `cluster/config.env`; the human asset table lives in `systems`; and their overlapping fields are checked in CI. If the cluster were to be destroyed, this repo (plus the secrets stored in S3) is the material needed to rebuild it from scratch.

---

## How It Works (The Big Picture)

The cluster has two types of nodes:

### Control Plane Nodes (the "managers")

These run the Kubernetes brain — the software that decides where containers should run, monitors health, and responds to commands. We have **3 control plane nodes** for high availability. If one goes down, the others keep the cluster running.

They share a **Virtual IP (VIP)** — a single IP address (10.69.112.62) that always points to whichever control plane node is currently active. This means tools and applications always connect to the same address, even if the active node changes.

### Worker Nodes (the "doers")

These run your actual applications. When you deploy a container, it gets placed on a worker node. We have **3 worker nodes**.

### The Flow

```
You (on your computer)
  |
  v
VIP 10.69.112.62
  |
  +-- control plane nodes listed in systems and cluster/config.env

Kubernetes schedules application pods onto:
  +-- worker nodes listed in systems and cluster/config.env
```

Use `systems` for the human node inventory and `cluster/config.env` for machine-readable node endpoints, role partition, VIP, and bootstrap data. [ADR-0002](docs/decision-records/repo/0002-use-short-talos-hostnames.md) explains the short hostname convention.

When you run a command like `kubectl apply -f my-app.yaml`, here's what happens:

1. Your command goes to the VIP (10.69.112.62)
2. The active control plane node receives it
3. Kubernetes decides which worker node should run your app
4. The worker node downloads and starts the container
5. Your app is now running and accessible

---

## Our Specific Cluster

### Node Inventory

The canonical inventory is split by audience:

- `cluster/config.env` is the machine source of truth for short hostname/IP endpoints, role partition, VIP, bootstrap node, and version pins.
- `systems` is the human source of truth for short hostnames, asset names, roles, IPs, install disks, NICs, and the bootstrap marker.

Their overlapping fields are checked by `scripts/check-node-inventory-sync.py` in CI. See [ADR-0002](docs/decision-records/repo/0002-use-short-talos-hostnames.md) for the hostname convention.

**Virtual IP (VIP):** 10.69.112.62 — shared between the three control plane nodes. This is the address you use for all Kubernetes API access.

**"Bootstrap Node"** means `cp1` was the first node to initialize the cluster. It's not special after that — all three control plane nodes are equal. However, during upgrades, the bootstrap node is always upgraded *last* as a safety measure.

### Naming Convention

The cluster uses short Talos hostnames (`cp1`–`cp3`, `w1`–`w3`) matching the live K8s node names. Asset names (`TDNHQ-TLO*`) are retained as a cross-reference to site-level physical-asset inventory. See [docs/decision-records/repo/0002-use-short-talos-hostnames.md](docs/decision-records/repo/0002-use-short-talos-hostnames.md).

Asset-name structure:
- **TDNHQ** = Site identifier (the physical location)
- **TLO** = Talos
- **MGT** = Management (control plane)
- **WRK** = Worker
- **01, 02, 03** = Sequence number

---

## What Software Is Installed

The cluster runs several layers of software. Here's each one, what it does, and why we need it:

| Software | Version | What It Does | Why We Need It |
|----------|---------|-------------|----------------|
| **TalosOS** | v1.13.2 | The operating system on each node. Secure, immutable, API-managed. | It's the foundation: every node runs this instead of Ubuntu, CentOS, etc. |
| **Kubernetes** | v1.36.0 | The container orchestration platform. Manages all running applications. | It's the core: this is what makes the cluster a cluster. |
| **Cilium** | 1.19.4 | Handles pod networking, replaces kube-proxy, and provides the Gateway API dataplane. | Without a CNI (Container Network Interface), containers on different nodes cannot talk to each other. |
| **CoreDNS** | bundled with Kubernetes | Translates service names to IP addresses inside the cluster. | So containers can find each other by name, such as `database`, instead of memorizing IP addresses. |
| **Flux** | v2.8.8 | Reconciles the Kubernetes manifests under `clusters/talos-cluster/`. | Keeps Git as the operational source of truth after bootstrap. |
| **Kyverno** | 3.8.1 | Provides Kubernetes admission policy, enforcing first-party image signatures while auditing upstream families. | Gives the cluster a policy engine without requiring ad hoc manual admission checks. |
| **Gateway API CRDs** | v1.4.1 | Defines the Kubernetes Gateway API resources used with Cilium. | Uses the upstream Gateway API model for application routing. |
| **metrics-server** | 3.13.0 | Collects CPU and memory usage from every node and pod. | Enables `kubectl top` and autoscaling signals. |
| **Longhorn** | 1.11.2 | Provides replicated block storage and the default `StorageClass`. | Applications that need persistent volumes get storage backed by the Talos `longhorn` user volume. |
| **postfinance/kubelet-csr-approver** | 1.2.14 | Automatically approves kubelet serving certificate requests that match this cluster's node identity rules. | Allows metrics-server to validate kubelet TLS against the cluster CA without manual certificate approval loops. |

---

## Current Architecture

This repository has two reconciliation paths:

- **Talos machine state** is generated from `cluster/config.env` and `cluster/patches/`, then applied with the Makefile and scripts in `scripts/`.
- **Kubernetes application state** is reconciled by Flux from `clusters/talos-cluster/`. Helm-based addons use `helm.toolkit.fluxcd.io/v2` `HelmRelease` resources, while Kustomize resources cover Gateway API CRDs, namespace hardening, tenant scaffolding, and encrypted secrets.

The current cluster stack is:

- **GitOps:** Flux `v2.8.8` bootstraps from `clusters/talos-cluster/flux-system/` and reconciles app and tenant manifests from this repository.
- **Networking and ingress:** Cilium `1.19.4` replaces kube-proxy and is the Gateway API dataplane. Gateway API `v1.4.1` CRDs and the `cilium` `GatewayClass` live under `clusters/talos-cluster/apps/gateway-api/`.
- **Policy:** Kyverno `3.8.1` is reconciled by Flux. First-party image signatures for `ghcr.io/nwarila-platform/*`, `ghcr.io/nwarila/*`, and `ghcr.io/the-hero-wars-guys/*` are enforced, so unsigned or unverified images are blocked at admission; upstream Flux, Cilium, Kyverno, and VSO images remain audit-only pending a re-signing registry (TD-0001/TD-0002).
- **Storage:** Longhorn `1.11.2` is the default replicated block-storage layer and writes to the Talos `longhorn` user volume at `/var/mnt/longhorn`.
- **Secrets:** SOPS with age encrypts Kubernetes Secret payload fields in git; Flux decrypts them at reconcile time using the in-cluster `sops-age` secret.
- **Safety net:** GitHub Actions validate configs, scan for secrets and compliance issues, and keep organization ADR mirrors synchronized. Flux also runs the `talos-drift-readonly` CronJob in-cluster to detect reduced read-only drift for version pins, node InternalIPs, and Flux health.

---

## Repository Layout

This is a tracked-layout summary, not a byte-for-byte `git ls-files` dump. Use `git ls-files` when you need the exact file list.

| Path | Purpose |
|------|---------|
| `cluster/config.env` | Machine source of truth for cluster identity, node endpoints, role partition, VIP, bootstrap node, and Talos/Kubernetes/Cilium/Longhorn version pins; overlapping fields are CI-guarded against `systems`. |
| `cluster/patches/` | Talos strategic-merge patches for common, control-plane, worker, firewall, volume, and node-specific machine settings. |
| `clusters/talos-cluster/flux-system/` | Flux bootstrap manifests and repository sync definition. |
| `clusters/talos-cluster/apps/` | Flux-reconciled platform apps: deploy repo references, Gateway API, kubelet CSR approver, Kyverno, metrics-server, namespace hardening, encrypted Vault AWS access material, and read-only drift detection. |
| `clusters/talos-cluster/tenants/` | Tenant namespace/network-policy definitions plus onboarding templates. |
| `addons/` | Out-of-band bootstrap Helm values retained for cluster rebuilds or adopted releases: `cilium`, `kubelet-csr-approver`, and `longhorn`. |
| `docs/` | Compliance notes and ADR mirrors split into org, template, and repo decision records. |
| `scripts/` | Operator automation used by the Makefile: generate, apply, bootstrap, health, upgrade, S3 sync, local drift helpers, snapshot, tenant onboarding, deploy-repo sync, and read-only drift tests. |
| `.github/workflows/` | CI, deploy, security, snapshot, compliance, tenant, deploy-repo sync, and org ADR synchronization workflows. |
| `.sops.yaml` | SOPS/age encryption policy for Kubernetes Secret payload fields. |
| `.github/CODEOWNERS`, `.github/renovate.json5`, `.pre-commit-config.yaml`, `.editorconfig` | Repository governance, dependency update, local validation, and editor-formatting controls. |
| `Makefile` | Operator command entry point. Run `make help` to see supported commands. |
| `systems` | Canonical human node inventory table with short hostnames, asset names, roles, IPs, install disks, NICs, and bootstrap marker; not used to generate or apply cluster configs, and CI-guarded against `cluster/config.env`. |

### Local Secret Mirror

The `.s3/` directory is a local, gitignored mirror of the production S3 secret bucket. It can contain Talos secrets, kubeconfigs, talosconfigs, and generated machine configs, so it must stay out of git. Operators use `make s3-push` and `make s3-pull` to synchronize that local state with the encrypted S3 bucket when needed.

---

## What You Need Before Starting

You need 3 command-line tools installed on your computer. Here's exactly what they are and how to get them:

### 1. `talosctl` — Talos Node Manager

**What it does:** Sends commands to TalosOS nodes. Used to apply configs, bootstrap the cluster, check health, view logs, and upgrade nodes.

**How to install:**

- **Windows:** Visit [https://github.com/siderolabs/talos/releases](https://github.com/siderolabs/talos/releases), download `talosctl-windows-amd64.exe`, rename it to `talosctl.exe`, and place it in a folder on your PATH (e.g., `C:\Users\YourName\bin\`).
- **macOS:** `brew install siderolabs/tap/talosctl`
- **Linux:** `curl -sL https://talos.dev/install | sh`

**How to verify it's installed:**

```bash
talosctl version --client --short
```

You should see output matching the `TALOS_VERSION` pin in `cluster/config.env`.

### 2. `kubectl` — Kubernetes CLI

**What it does:** Sends commands to Kubernetes. Used to deploy applications, check pod status, view logs, and manage resources.

**How to install:**

- **Windows:** `choco install kubernetes-cli` (if you have Chocolatey), or download from [https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/](https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/)
- **macOS:** `brew install kubectl`
- **Linux:** `curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && chmod +x kubectl && sudo mv kubectl /usr/local/bin/`

**How to verify it's installed:**

```bash
kubectl version --client
```

You should see output mentioning `Client Version: v1.32.x` (or similar).

### 3. `helm` — Kubernetes Package Manager

**What it does:** Installs pre-packaged applications (called "charts") into Kubernetes. Think of it like an app store for Kubernetes.

**How to install:**

- **Windows:** `choco install kubernetes-helm` or download from [https://github.com/helm/helm/releases](https://github.com/helm/helm/releases)
- **macOS:** `brew install helm`
- **Linux:** `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash`

**How to verify it's installed:**

```bash
helm version --short
```

You should see output like: `v3.16.4+g7877b45`

### 4. `aws` CLI (Optional — only needed for S3 sync)

**What it does:** Communicates with Amazon Web Services. Used only for pushing/pulling secrets to/from the S3 bucket.

**How to install:** [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/)

### Verify Everything At Once

Run this command from the root of the repository:

```bash
make init
```

This checks that all required tools are installed and prints their versions. If anything is missing, it tells you.

---

## Setup From Scratch (Full Walkthrough)

This section walks you through setting up the cluster from zero. Follow every step in order.

### Step 1: Install the Tools

Install `talosctl`, `kubectl`, and `helm` as described in [What You Need Before Starting](#what-you-need-before-starting).

### Step 2: Clone This Repository

```bash
git clone https://github.com/YOUR_ORG/TDNHQ-TALCL01.git
cd TDNHQ-TALCL01
```

Verify prerequisites:

```bash
make init
```

### Step 3: Generate Machine Configs

This step creates two things:

1. **A secrets bundle** (only on the first run) — contains encryption keys and certificates that prove nodes belong to this cluster. This file is the crown jewels; anyone who has it can control the cluster.

2. **Per-node machine configs** — a complete configuration file for each of the 6 nodes, created by combining the base config with the common, role-specific, and node-specific patches.

```bash
make generate
```

**What you should see:**

```
==> Generating Talos secrets bundle...
==> Generating base machine configs...
==> Generating per-node control plane configs...
==> Generating per-node worker configs...
==> Generation complete!
```

The per-node names and IPs come from `cluster/config.env`; use `systems` for the asset-name, install-disk, and NIC cross-reference.

**Where do the files go?** Into the `.s3/` folder (which is gitignored and never committed).

### Step 4: Validate the Configs

This checks that every generated config file is structurally valid and would be accepted by TalosOS.

```bash
make validate
```

**What you should see:** Each file followed by "is valid for metal mode". If any file shows an error, stop and fix the issue before proceeding.

### Step 5: Boot the Talos Nodes

Each physical machine needs to be booted from the TalosOS ISO image.

1. Download the Talos ISO for your version from [https://github.com/siderolabs/talos/releases](https://github.com/siderolabs/talos/releases) (look for `metal-amd64.iso` or similar)
2. Write the ISO to a USB drive (using Rufus, Etcher, or `dd`)
3. Boot each machine from the USB drive
4. The machine will start in **maintenance mode** — it's running Talos but waiting for a config

You should be able to reach each node's Talos API on port 50000. Test with:

```bash
talosctl version --nodes 10.69.112.63 --insecure
```

If you see a client version and a server response (even if the server version shows an error about maintenance mode), the node is reachable and ready.

### Step 6: Apply Configs to the Nodes

Now send each node its specific configuration. Since the nodes don't have certificates yet (they're brand new), you must use the `--insecure` flag:

```bash
make apply-insecure
```

This sends the generated config files to all 6 nodes. Each node will:

1. Receive its configuration
2. Write TalosOS to its designated disk
3. Reboot from the installed disk
4. Start all Talos services

**Wait about 2-3 minutes** for the nodes to install and reboot. You can check if they're back with:

```bash
talosctl version --talosconfig .s3/configs/talosconfig --nodes 10.69.112.63 --short
```

You should see both client and server version information.

**IMPORTANT:** After the first apply, the talosconfig file needs endpoints configured:

```bash
talosctl config endpoint 10.69.112.63 10.69.112.64 10.69.112.65 --talosconfig .s3/configs/talosconfig
```

### Step 7: Bootstrap the Cluster

**This step runs ONCE EVER.** It initializes the distributed database (etcd) that Kubernetes uses to store all cluster state.

```bash
make bootstrap
```

The script will:

1. Ask you to confirm by typing `yes`
2. Bootstrap etcd on the first control plane node (`cp1`)
3. Wait for the cluster to become healthy (up to 10 minutes)
4. Fetch your kubeconfig (the credential used by `kubectl`)

**NOTE:** The health check may fail with a timeout at this stage. This is normal — the cluster needs a CNI (networking plugin) before nodes become fully "Ready." As long as you see etcd, kubelet, and apid showing "OK," proceed to the next step.

If the health check times out, manually fetch the kubeconfig:

```bash
talosctl kubeconfig --talosconfig .s3/configs/talosconfig --nodes 10.69.112.63 --force .s3/configs/kubeconfig
```

Verify Kubernetes is running (nodes will show "NotReady" — that's expected):

```bash
export KUBECONFIG=.s3/configs/kubeconfig
kubectl get nodes
```

### Step 8: Install Cilium (Networking)

The cluster currently has no networking between pods. The nodes show "NotReady" because there's no CNI installed. Cilium is our CNI.

**If you're on Windows / Git Bash**, you MUST run this first to prevent path mangling:

```bash
export MSYS_NO_PATHCONV=1
```

Add the Cilium Helm repository and install:

```bash
export KUBECONFIG=.s3/configs/kubeconfig
source cluster/config.env

helm repo add cilium https://helm.cilium.io/
helm repo update

helm install cilium cilium/cilium \
    --version "${CILIUM_VERSION}" \
    --namespace kube-system \
    -f addons/cilium/values.yaml
```

**Wait 1-2 minutes**, then check that all nodes become "Ready":

```bash
kubectl get nodes
```

All 6 nodes should show `STATUS: Ready`. If they don't after 3 minutes, check the Cilium pods:

```bash
kubectl get pods -n kube-system -l k8s-app=cilium
```

All Cilium pods should show `1/1 Running`.

### Step 9: Approve Kubelet Certificates

When nodes first start, they request security certificates for their kubelet (the agent that runs containers). These need to be approved once.

Check for pending certificate requests:

```bash
kubectl get csr
```

Approve all pending ones:

```bash
kubectl get csr --no-headers | grep Pending | awk '{print $1}' | while read csr; do
    kubectl certificate approve "$csr"
done
```

Do not install a standalone approver here. Flux reconciles the accepted `postfinance/kubelet-csr-approver` release from `clusters/talos-cluster/apps/kubelet-csr-approver/` in the next step. See [ADR-0005](docs/decision-records/repo/0005-kubelet-csr-approver.md).

### Step 10: Reconcile GitOps Addons

Flux owns the remaining Kubernetes platform addons under `clusters/talos-cluster/apps/`. The committed `HelmRelease` resources install or adopt:

- `postfinance/kubelet-csr-approver` `1.2.14`
- `metrics-server` `3.13.0`
- `kyverno` `3.8.1`
- `longhorn` `1.11.2`
- Gateway API `v1.4.1` CRDs and the `cilium` `GatewayClass`
- namespace hardening and tenant envelopes

```bash
kubectl apply -k clusters/talos-cluster/flux-system
```

Flux's `Kustomization` points at `./clusters/talos-cluster`, so once the bootstrap Git and SOPS age secrets exist in `flux-system`, Flux reconciles `flux-system/`, `apps/`, and `tenants/` from git.

```bash
kubectl -n flux-system get gitrepositories,kustomizations
kubectl -n kube-system get helmreleases.helm.toolkit.fluxcd.io
kubectl -n kyverno get helmreleases.helm.toolkit.fluxcd.io
kubectl -n longhorn-system get helmreleases.helm.toolkit.fluxcd.io
kubectl get gatewayclass
```

metrics-server now uses chart defaults and validates kubelet serving certificates against the cluster CA. The previous kubelet TLS bypass workaround is not part of the current values.

**Longhorn storage** is now Flux-managed at `clusters/talos-cluster/apps/longhorn/`.
The `longhorn` HelmRelease adopts the existing release, pins chart version
`1.11.2`, and inlines values that mirror `addons/longhorn/values.yaml`.
The `longhorn-system` namespace is declared with the privileged PodSecurity
labels because Longhorn instance-manager and engine pods require privileged mode
(hostPath and raw block-device access).

The manual Helm path is retained only as break-glass or DR bootstrap context when
Flux is unavailable. Normal operation must flow through the GitOps manifests:

```bash
source cluster/config.env
helm repo add longhorn https://charts.longhorn.io
helm repo update

# Create the namespace with the privileged PodSecurity label — Longhorn
# instance-manager + engine pods require privileged mode (hostPath, raw
# block-device access). See the longhorn-system namespace label in the
# live cluster.
kubectl create namespace longhorn-system
kubectl label namespace longhorn-system \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/audit=privileged \
    pod-security.kubernetes.io/warn=privileged

helm install longhorn longhorn/longhorn \
    --version "${LONGHORN_VERSION}" \
    --namespace longhorn-system \
    -f addons/longhorn/values.yaml
```

The `values.yaml` makes `longhorn` the cluster's default `StorageClass` and sets
`defaultDataPath: /var/mnt/longhorn` so Longhorn writes to the Talos
`UserVolumeConfig` declared in `cluster/patches/volumes.yaml` (50-240 GiB carved
out of every node's system disk). Vault uses the separate Flux-owned
`longhorn-vault` StorageClass for 3-replica, hard node anti-affinity volumes.
See [ADR-0007](docs/decision-records/repo/0007-capture-longhorn-as-managed-addon.md),
[ADR-0013](docs/decision-records/repo/0013-use-dedicated-vault-longhorn-storageclass.md),
and [ADR-0022](docs/decision-records/repo/0022-longhorn-under-flux-gitops.md)
for the rationale behind these storage defaults and the Flux adoption.

### Step 11: Verify Everything Works

Check that all pods are running:

```bash
kubectl get pods -A
```

Every pod should show `Running` and have READY `1/1` (or `2/2`, etc.). The only exception is completed `Job` pods which show `Completed`.

Check resource usage:

```bash
kubectl top nodes
```

You should see CPU and memory usage for all 6 nodes.

Run the full health check:

```bash
make health
```

### Step 12: Back Up Your Secrets

Push all secrets to the S3 bucket for safekeeping:

```bash
make s3-push
```

This uploads everything in `.s3/` to AWS S3, encrypted with KMS.

**You're done.** The cluster is fully operational.

---

## Day-to-Day Operations

### Checking Cluster Health

```bash
make health
```

This runs a comprehensive check: Talos service health, node versions, Kubernetes node and pod status.

For a quick check:

```bash
export KUBECONFIG=.s3/configs/kubeconfig
kubectl get nodes            # Are all nodes Ready?
kubectl get pods -A          # Are all pods Running?
kubectl top nodes            # CPU/memory usage
```

### Changing a Cluster Setting

1. Edit the appropriate file in `cluster/patches/`:
   - **All nodes:** `common.yaml`
   - **Control plane only:** `controlplane.yaml`
   - **Workers only:** `worker.yaml`
   - **One specific node:** `cp1.yaml` / `cp2.yaml` / … / `w3.yaml`

2. Regenerate and validate:

   ```bash
   make generate
   make validate
   ```

3. Apply the new config:

   ```bash
   make apply
   ```

   To target a specific node:

   ```bash
   make apply NODES="cp1"
   ```

Some changes apply without a reboot. Others require a reboot — Talos will tell you in the output.

### Upgrading Talos to a New Version

1. Open `cluster/config.env`
2. Change the `TALOS_VERSION` line to the new version (e.g., `v1.13.0`)
3. Regenerate, validate, and upgrade:

   ```bash
   make generate
   make validate
   make upgrade
   ```

The upgrade happens one node at a time in this order (safest to most critical):

1. Worker nodes first (`w1`, `w2`, `w3`)
2. Non-bootstrap control plane (`cp2`, `cp3`)
3. Bootstrap control plane (`cp1`) — always last

Each node is rebooted with the new version, and the script waits for it to become healthy before moving to the next one.

To upgrade only specific nodes:

```bash
make upgrade NODES="w1"
```

### Adding a New Worker Node

1. **Edit `cluster/config.env` and `systems`** — add the new node to the `WORKER_NODES` line using the next short-name ordinal (`w4`, `w5`, …), and add the complete `systems` row with asset name, `worker` role, IP, install disk, NIC, and `no` bootstrap marker:

   ```bash
   WORKER_NODES="w1:10.69.112.68 w2:10.69.112.69 w3:10.69.112.70 w4:10.69.112.71"
   ```

2. **Create a patch file** at `cluster/patches/w4.yaml` (filename = Talos hostname per [ADR-0002](docs/decision-records/repo/0002-use-short-talos-hostnames.md)):

   ```yaml
   machine:
     install:
       disk: /dev/nvme0n1  # Confirm against the new node's actual system disk
     network:
       interfaces:
         - deviceSelector:
             physical: true
           addresses:
             - 10.69.112.71/24
           routes:
             - network: 0.0.0.0/0
               gateway: 10.69.112.1
   ```

   > **Finding the disk:** Boot the new node from the Talos ISO and run:
   > `talosctl get systemdisk --nodes <IP> --insecure`

3. **Generate and validate:**

   ```bash
   make generate
   make validate
   ```

4. **Boot the new node** from the Talos ISO.

5. **Apply the config:**

   ```bash
   make apply-insecure NODES="w4"
   ```

6. **Approve its certificate** (if the auto-approver hasn't done it yet):

   ```bash
   kubectl get csr | grep Pending | awk '{print $1}' | xargs kubectl certificate approve
   ```

### Removing a Worker Node

1. Drain the node (safely move all workloads off it):

   ```bash
   kubectl drain w2 --ignore-daemonsets --delete-emptydir-data
   ```

2. Delete the node from Kubernetes:

   ```bash
   kubectl delete node w2
   ```

3. Remove the node from `WORKER_NODES` in `cluster/config.env`, remove its complete row from `systems`, and delete `cluster/patches/w2.yaml`.

4. Power off or repurpose the physical machine.

### Recovering Secrets on a New Machine

If you're setting up on a new computer (or your `.s3/` folder was lost):

```bash
make s3-pull
```

This downloads all secrets from the AWS S3 bucket. You then have full access to manage the cluster.

### Disaster Recovery

Stage-0 S3 storage holds rebuild-critical secrets and access material only.
Operational state snapshots move to the future Stage-1 local backup server:
etcd snapshots for Kubernetes state, Vault Raft snapshots for PKI/trust state,
and later Longhorn/PV data.

The old `etcd Snapshot` workflow is manual-only and remains disabled for
scheduled use until it is retargeted to Stage-1. ADR-0006 is superseded by
[ADR-0014](docs/decision-records/repo/0014-use-stage-1-local-backup-server-for-dr.md),
which defines the backup/DR architecture, cadence, retention, interim capture
posture, and monitoring requirements.

Restore is not accepted as working until it is drilled. Use
[Backup And DR Restore Drill](docs/runbooks/restore-drill-backup-dr.md) for the
owner-gated etcd and Vault Raft restore procedures and pass criteria.

### Deploying Your Own Application

1. Create Kubernetes manifests for your application, such as a Deployment, Service, and optionally Gateway API routing.
2. Prefer committing those manifests under the appropriate GitOps app or tenant path so Flux can reconcile them. For a one-off manual test, apply them directly:

   ```bash
   kubectl apply -f my-app.yaml
   ```

3. Check that it's running:

   ```bash
   kubectl get pods
   ```

Tenant scaffolding lives under `clusters/talos-cluster/tenants/`; deploy-repository references live under `clusters/talos-cluster/apps/deploy-*`.

---

## CI/CD (Automated Pipelines)

Repository-owned GitHub Actions workflows include:

| Purpose | Workflow file | What it does |
|---------|---------------|--------------|
| Validate | `validate.yaml` | Runs PR validation for scripts, YAML, generated Talos configs, and secret hygiene. |
| Security | `security.yaml` | Runs Gitleaks and the config audit on PRs, weekly schedule, and manual dispatch. |
| etcd snapshot | `etcd-snapshot.yaml` | Manual-only placeholder pending Stage-1 local backup server retargeting. |
| Compliance | `kubescape.yaml` | Runs the pinned Kubescape CIS Kubernetes scan and uploads SARIF to GitHub Code Scanning. |
| ARC smoke | `arc-smoke.yaml` | Manually verifies the `nwarila-talos-arc-ci` runner scale set can execute a job. |
| Tenant onboarding | `onboard-tenant.yaml` | Manually scaffolds tenant namespace and network-policy manifests. |
| Deploy repo sync | `sync-deploy-repos.yaml` | Discovers deployment repositories and refreshes the generated Flux deploy app entries. |
| Org ADR sync | `org-adr-sync.yaml` | Mirrors organization ADRs into `docs/decision-records/org/` on PRs, schedule, and manual dispatch. |
| Org ADR auto-sync | `org-adr-auto-sync.yaml` | Scheduled/manual automation for keeping mirrored org ADRs current. |

Runtime drift detection is no longer a GitHub Actions workflow. Flux reconciles
`clusters/talos-cluster/apps/talos-drift/`, which runs an hourly in-cluster
CronJob using a SOPS-encrypted Talos `os:reader` config and a least-privilege
Kubernetes ServiceAccount. The reduced detector covers version pins, node
InternalIPs, and Flux health. It intentionally does not cover Talos
machine-config drift because `machineconfig` is admin-only.

Talos apply and upgrade remain manual/loop operations from an operator workstation using `make apply` and `make upgrade`. CI-based Talos apply was intentionally removed so public-repo workflows do not hold a Talos admin config. The etcd snapshot and Kubescape workflows require self-hosted runner access to the private cluster network or its credentials. GitHub-hosted runners only handle checks that can run from the repository contents.

---

## Security

The cluster has multiple layers of security:

| Layer | What It Does |
|-------|-------------|
| **TalosOS** | No SSH, no shell, no package manager. The OS is immutable and API-only. Attackers can't install malware or modify the OS. |
| **PodSecurity** | Kubernetes enforces the `baseline` security standard cluster-wide. Containers can't run as root, use host networking (unless explicitly exempted), or escalate privileges. The `restricted` standard is applied in audit/warn mode to flag risky configs. |
| **Gitleaks** | Scans for leaked secrets both in pre-commit hooks (before you push) and in CI (on every PR). Catches accidentally committed passwords, API keys, or certificates. |
| **ShellCheck** | Lints all shell scripts for common bugs and security issues (like unquoted variables that could cause command injection). |
| **Private key detection** | Pre-commit hook specifically checks for PEM-encoded private keys in staged files. |
| **CODEOWNERS** | Changes to cluster configuration, scripts, and CI pipelines require review from designated owners. No one can push unreviewed changes to critical files. |
| **Renovate** | Automatically proposes dependency updates under the repository Renovate policy. |
| **S3 + KMS encryption** | All secrets are encrypted at rest using AWS KMS when stored in S3. |
| **Kubelet cert auto-approval** | Only kubelet serving certificates are auto-approved — not arbitrary certificate requests. |

---

## Troubleshooting

### "NotReady" nodes after bootstrap

**Cause:** No CNI is installed. Without a networking plugin, Kubernetes considers nodes unhealthy.

**Fix:** Install Cilium (Step 8).

### Cilium pods stuck in `Init:CreateContainerError`

**Cause (Windows only):** Git Bash translated Unix paths (like `/sys/fs/cgroup`) to Windows paths.

**Fix:** Set `export MSYS_NO_PATHCONV=1` before running `helm install`. Uninstall the broken release with `helm uninstall cilium -n kube-system` and reinstall.

### kube-apiserver crash-looping

**Cause:** Usually a configuration error in the control plane patch (e.g., duplicate values in PodSecurity exemptions).

**Fix:** Check the apiserver logs:

```bash
talosctl logs --talosconfig .s3/configs/talosconfig --nodes 10.69.112.63 -k kube-system/kube-apiserver-tdnhq-tlomgt01:kube-apiserver
```

Look for the specific error message, fix the patch file, regenerate, validate, and re-apply.

### metrics-server shows 0/1 Ready

**Cause:** metrics-server validates kubelet serving certificates against the cluster CA. If it is not Ready, first check whether kubelet serving CSRs are pending or whether the Flux-managed kubelet CSR approver is unhealthy.

**Fix:**

```bash
kubectl get csr
kubectl -n kube-system get helmrelease kubelet-csr-approver
kubectl -n kube-system get pods -l app.kubernetes.io/name=kubelet-csr-approver
```

After any missing CSRs are approved or the approver has recovered, restart metrics-server:

```bash
kubectl delete pod -n kube-system -l app.kubernetes.io/name=metrics-server
```

### "failed to determine endpoints" when using talosctl

**Cause:** The talosconfig file has empty endpoints.

**Fix:**

```bash
talosctl config endpoint 10.69.112.63 10.69.112.64 10.69.112.65 --talosconfig .s3/configs/talosconfig
```

### NTP "kiss of death" or time sync errors

**Cause:** The NTP server is refusing requests or is unreachable from the network.

**Impact:** Usually not critical — the nodes will eventually sync or use their hardware clock. If clocks are significantly off, TLS certificates may be rejected.

**Fix:** Edit `cluster/patches/common.yaml` and change the NTP server under `machine.time.servers` to one that works on your network.

### A node won't come back after reboot

1. Check if the node's Talos API is reachable:

   ```bash
   talosctl version --nodes <IP> --insecure
   ```

2. If it responds: Check dmesg for errors:

   ```bash
   talosctl dmesg --talosconfig .s3/configs/talosconfig --nodes <IP>
   ```

3. If it doesn't respond: The node may need to be physically checked (network cable, power, BIOS boot order).

---

## Windows / Git Bash Notes

If you are running these commands from Git Bash (MSYS2) on Windows, there is one critical thing to know:

**Git Bash automatically converts Unix-style paths to Windows paths.** For example, `/sys/fs/cgroup` becomes `C:/Program Files/Git/sys/fs/cgroup`. This breaks Helm values that contain Unix paths.

**The fix:** Before running ANY `helm` command, set this environment variable:

```bash
export MSYS_NO_PATHCONV=1
```

You can add this to your `~/.bashrc` to make it permanent:

```bash
echo 'export MSYS_NO_PATHCONV=1' >> ~/.bashrc
```

This does NOT affect other tools — it only disables path conversion for the current session.

---

## Quick Reference (All Commands)

Run `make help` to see this list in your terminal.

| Command | What It Does |
|---------|-------------|
| `make init` | Verify that all required tools are installed |
| `make generate` | Generate machine configs from patches + secrets |
| `make validate` | Validate all generated machine configs |
| `make apply` | Apply configs to all nodes |
| `make apply NODES="X Y"` | Apply configs to specific nodes only |
| `make apply-insecure` | Apply configs in insecure mode (first-time setup) |
| `make bootstrap` | Bootstrap the cluster (run ONCE EVER) |
| `make upgrade` | Rolling upgrade of Talos on all nodes |
| `make upgrade NODES="X"` | Upgrade specific nodes only |
| `make health` | Run comprehensive cluster health checks |
| `make kubeconfig` | Fetch a fresh kubeconfig from the cluster |
| `make s3-push` | Upload local `.s3/` to AWS S3 (encrypted) |
| `make s3-pull` | Download from AWS S3 to local `.s3/` |
| `make clean` | Remove generated configs and local client configs; keep Talos secrets bundle |
| `make reset` | Remove EVERYTHING including secrets (asks for confirmation) |

---

## Glossary

| Term | What It Means |
|------|--------------|
| **API** | Application Programming Interface — a way for programs to talk to each other. When we say "Talos is API-managed," we mean you control it by sending structured commands to it, not by logging in and typing shell commands. |
| **Bootstrap** | The initial setup of the cluster's internal database. Only done once when creating a new cluster. |
| **Certificate (cert)** | A digital document that proves identity, like a passport. Nodes use certificates to prove they belong to this cluster. |
| **Cilium** | The networking plugin that lets containers on different nodes communicate with each other. |
| **Cluster** | A group of computers (nodes) working together as a single system. |
| **CNI** | Container Network Interface — the plugin that provides networking between containers. Cilium is our CNI. |
| **ConfigMap** | A Kubernetes object that stores non-secret configuration data that pods can read. |
| **Container** | A lightweight, isolated package containing an application and everything it needs to run. Think of it as a zip file that includes the app, its libraries, and its settings — and can run anywhere. |
| **Control Plane** | The nodes that run Kubernetes management software (API server, scheduler, controller). They don't run your applications — they manage the cluster. |
| **CoreDNS** | The DNS server running inside the cluster that lets pods find each other by name. |
| **CSR** | Certificate Signing Request — a request from a node asking the cluster to issue it a certificate. |
| **DaemonSet** | A Kubernetes resource that runs exactly one copy of a pod on every node (or every node matching a selector). |
| **Deployment** | A Kubernetes resource that defines what containers to run and how many copies. |
| **etcd** | A distributed key-value database used by Kubernetes to store all cluster state (what pods are running, what configs exist, etc.). It runs on control plane nodes. |
| **Helm** | A package manager for Kubernetes. Helm "charts" are pre-packaged applications. |
| **Immutable** | Cannot be changed. TalosOS is immutable — you can't modify files on it, install packages, or SSH into it. |
| **Ingress** | A Kubernetes resource that defines how external HTTP/HTTPS traffic reaches services inside the cluster. |
| **KubePrism** | A local proxy that Talos runs on each node to provide a reliable connection to the Kubernetes API. Listens on `127.0.0.1:7445`. |
| **kubeconfig** | A file containing the credentials and endpoint needed to connect `kubectl` to a Kubernetes cluster. |
| **kubectl** | The command-line tool for interacting with Kubernetes. |
| **kubelet** | The agent running on every node that actually starts and manages containers. |
| **kube-proxy** | A default Kubernetes component that handles network routing. We replaced it with Cilium for better performance. |
| **Namespace** | A virtual partition inside Kubernetes. Used to separate different applications or environments (e.g., `kube-system` for system components, `poc` for our proof of concept). |
| **Node** | A single computer (physical or virtual) in the cluster. |
| **Patch** | A small file that modifies part of a larger configuration. Instead of duplicating the entire config, you write only the parts you want to change. |
| **Pod** | The smallest unit in Kubernetes — one or more containers running together on the same node. Most pods contain exactly one container. |
| **PodSecurity** | A Kubernetes feature that restricts what pods are allowed to do (e.g., preventing them from running as root). |
| **Service** | A Kubernetes resource that provides a stable network address for a group of pods. Even if pods restart and get new IPs, the Service address stays the same. |
| **StorageClass** | Defines what kind of storage is available in the cluster. `local-path` means storage is on the node's local disk. |
| **Strategic merge patch** | A way to merge configuration changes. Instead of replacing the entire config, it merges your changes into the existing config, keeping everything you didn't change. |
| **talosconfig** | A file containing the credentials and endpoint needed to connect `talosctl` to Talos nodes. |
| **talosctl** | The command-line tool for interacting with TalosOS nodes. |
| **VIP** | Virtual IP — a shared IP address that floats between multiple nodes. Whichever node is currently active "owns" the VIP. This provides high availability. |
| **Worker** | A node that runs your applications. It does not run control plane components. |
| **YAML** | A file format used for configuration. It uses indentation to show structure (like Python). Nearly all Kubernetes configs are YAML files. |
