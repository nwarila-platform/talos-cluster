# TDNHQ-TALCL01

## Table of Contents

1. [What Is This?](#what-is-this)
2. [How It Works (The Big Picture)](#how-it-works-the-big-picture)
3. [Our Specific Cluster](#our-specific-cluster)
4. [What Software Is Installed](#what-software-is-installed)
5. [Every File In This Repository Explained](#every-file-in-this-repository-explained)
6. [What You Need Before Starting](#what-you-need-before-starting)
7. [Setup From Scratch (Full Walkthrough)](#setup-from-scratch-full-walkthrough)
   - [Step 1: Install the Tools](#step-1-install-the-tools)
   - [Step 2: Clone This Repository](#step-2-clone-this-repository)
   - [Step 3: Generate Machine Configs](#step-3-generate-machine-configs)
   - [Step 4: Validate the Configs](#step-4-validate-the-configs)
   - [Step 5: Boot the Talos Nodes](#step-5-boot-the-talos-nodes)
   - [Step 6: Apply Configs to the Nodes](#step-6-apply-configs-to-the-nodes)
   - [Step 7: Bootstrap the Cluster](#step-7-bootstrap-the-cluster)
   - [Step 8: Install Cilium (Networking)](#step-8-install-cilium-networking)
   - [Step 9: Approve Kubelet Certificates](#step-9-approve-kubelet-certificates)
   - [Step 10: Install Remaining Addons](#step-10-install-remaining-addons)
   - [Step 11: Verify Everything Works](#step-11-verify-everything-works)
   - [Step 12: Deploy the Proof of Concept](#step-12-deploy-the-proof-of-concept)
   - [Step 13: Back Up Your Secrets](#step-13-back-up-your-secrets)
8. [Day-to-Day Operations](#day-to-day-operations)
   - [Checking Cluster Health](#checking-cluster-health)
   - [Changing a Cluster Setting](#changing-a-cluster-setting)
   - [Upgrading Talos to a New Version](#upgrading-talos-to-a-new-version)
   - [Adding a New Worker Node](#adding-a-new-worker-node)
   - [Removing a Worker Node](#removing-a-worker-node)
   - [Recovering Secrets on a New Machine](#recovering-secrets-on-a-new-machine)
   - [Deploying Your Own Application](#deploying-your-own-application)
9. [CI/CD (Automated Pipelines)](#cicd-automated-pipelines)
10. [Security](#security)
11. [Troubleshooting](#troubleshooting)
12. [Windows / Git Bash Notes](#windows--git-bash-notes)
13. [Quick Reference (All Commands)](#quick-reference-all-commands)
14. [Glossary](#glossary)

---

## What Is This?

This repository contains everything needed to deploy, manage, and operate a **Kubernetes cluster** running on **TalosOS**.

Here's what those terms mean in plain language:

- **Kubernetes** is a system that runs applications inside lightweight packages called "containers." Instead of installing software directly on a computer, you put it in a container that can run anywhere. Kubernetes manages many of these containers across multiple computers, making sure they stay running, can handle traffic, and recover from failures.

- **TalosOS** is the operating system installed on each computer (called a "node") in the cluster. Unlike Windows or a regular Linux install, TalosOS is *immutable* — you cannot SSH into it, you cannot install software on it, and you cannot change files on it. It is managed entirely through an API (a programmatic interface). This makes it extremely secure and consistent. If a node has a problem, you don't debug it — you replace it.

- **A cluster** is a group of computers working together as one. Ours has 6 physical machines (nodes).

This repository is the **single source of truth** for the entire cluster. Every setting, every configuration, every version number lives here. If the cluster were to be destroyed, this repo (plus the secrets stored in S3) is everything you need to rebuild it from scratch.

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
  +-- cp1 / TDNHQ-TLOMGT01 / 10.69.112.63 (bootstrap control plane)
  +-- cp2 / TDNHQ-TLOMGT02 / 10.69.112.64 (control plane)
  +-- cp3 / TDNHQ-TLOMGT03 / 10.69.112.65 (control plane)

Kubernetes schedules application pods onto:
  +-- w1 / TDNHQ-TLOWRK01 / 10.69.112.68 (worker)
  +-- w2 / TDNHQ-TLOWRK02 / 10.69.112.69 (worker)
  +-- w3 / TDNHQ-TLOWRK03 / 10.69.112.70 (worker)
```

When you run a command like `kubectl apply -f my-app.yaml`, here's what happens:

1. Your command goes to the VIP (10.69.112.62)
2. The active control plane node receives it
3. Kubernetes decides which worker node should run your app
4. The worker node downloads and starts the container
5. Your app is now running and accessible

---

## Our Specific Cluster

### Node Inventory

| Hostname | Asset Name | Role | IP Address | Install Disk | NIC |
|----------|------------|------|------------|-------------|-----|
| cp1 | TDNHQ-TLOMGT01 | Control Plane (Bootstrap) | 10.69.112.63 | /dev/nvme0n1 | eno1 |
| cp2 | TDNHQ-TLOMGT02 | Control Plane | 10.69.112.64 | /dev/nvme0n1 | eno1 |
| cp3 | TDNHQ-TLOMGT03 | Control Plane | 10.69.112.65 | /dev/nvme0n1 | eno1 |
| w1  | TDNHQ-TLOWRK01 | Worker | 10.69.112.68 | /dev/nvme0n1 | eno1 |
| w2  | TDNHQ-TLOWRK02 | Worker | 10.69.112.69 | /dev/nvme0n1 | eno1 |
| w3  | TDNHQ-TLOWRK03 | Worker | 10.69.112.70 | /dev/nvme0n1 | eno1 |

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
| **TalosOS** | v1.12.5 | The operating system on each node. Secure, immutable, API-managed. | It's the foundation — every node runs this instead of Ubuntu, CentOS, etc. |
| **Kubernetes** | v1.35.2 | The container orchestration platform. Manages all running applications. | It's the core — this is what makes the cluster a cluster. |
| **Cilium** | v1.16.6 | Handles all networking between containers, and replaces the default kube-proxy. | Without a CNI (Container Network Interface), containers on different nodes can't talk to each other. Cilium is the best production choice. |
| **CoreDNS** | (bundled) | Translates service names to IP addresses inside the cluster. | So containers can find each other by name (e.g., "database") instead of memorizing IP addresses. |
| **metrics-server** | v0.8.0 | Collects CPU and memory usage from every node and pod. | Enables `kubectl top` to see resource usage, and enables auto-scaling features. |
| **ingress-nginx** | v1.15.0 | Receives incoming web traffic (HTTP/HTTPS) and routes it to the right application. | Without an ingress controller, there's no way to expose web applications to users. |
| **local-path-provisioner** | v0.0.30 | Creates storage volumes on the local disk when applications request persistent storage. | Some applications need to save data to disk. This provides the simplest way to do that. |
| **kubelet-serving-cert-approver** | latest | Automatically approves security certificate requests from nodes. | Without this, you'd have to manually approve certificates every time a node restarts or renews certs. |

---

## Every File In This Repository Explained

```
TDNHQ-TALCL01/
│
├── cluster/                          # CLUSTER CONFIGURATION
│   │
│   ├── config.env                    # The SINGLE SOURCE OF TRUTH for all settings.
│   │                                 # Contains version numbers, IP addresses, node
│   │                                 # definitions, and S3 settings. If you need to
│   │                                 # change a version or add a node, this is where
│   │                                 # you do it.
│   │
│   └── patches/                      # Configuration patches for Talos nodes.
│       │                             # These are NOT full configs — they are small
│       │                             # files that customize the base config.
│       │
│       ├── common.yaml               # Settings applied to EVERY node (all 6).
│       │                             # Contains: DNS servers, NTP time servers,
│       │                             # kernel settings, kubelet settings.
│       │
│       ├── controlplane.yaml         # Settings applied to ONLY the 3 control plane
│       │                             # nodes. Contains: Cilium CNI config, API server
│       │                             # certificate SANs, PodSecurity policy, etcd
│       │                             # metrics, scheduler/controller-manager settings.
│       │
│       ├── worker.yaml               # Settings applied to ONLY the 3 worker nodes.
│       │                             # Contains: kubelet node IP subnet filter.
│       │
│       ├── cp1.yaml                  # Settings for THIS SPECIFIC NODE ONLY.
│       ├── cp2.yaml                  # Each file contains: the install disk path,
│       ├── cp3.yaml                  # the node's static IP address, default route,
│       ├── w1.yaml                   # and (for CP nodes) the VIP address.
│       ├── w2.yaml                   # File basename = the node's Talos hostname.
│       └── w3.yaml
│
├── addons/                           # CLUSTER ADD-ON CONFIGURATIONS
│   │
│   ├── cilium/
│   │   └── values.yaml              # Helm values for Cilium. Contains settings
│   │                                 # specific to running Cilium on TalosOS (cgroup
│   │                                 # paths, capabilities, KubePrism proxy config).
│   │
│   ├── metrics-server/
│   │   └── values.yaml              # Helm values for metrics-server. Enables
│   │                                 # insecure TLS to kubelet (required on Talos).
│   │
│   ├── ingress-nginx/
│   │   └── values.yaml              # Helm values for ingress-nginx. Configures it
│   │                                 # as a DaemonSet using host networking (required
│   │                                 # for bare metal — no cloud load balancer).
│   │
│   └── poc/                          # PROOF OF CONCEPT deployment
│       ├── namespace.yaml            # Creates the "poc" namespace with security labels.
│       ├── deployment.yaml           # Deploys 2 nginx containers serving a status page.
│       └── service.yaml              # Creates a Service and Ingress so the page is
│                                     # accessible via HTTP on the worker node IPs.
│
├── scripts/                          # AUTOMATION SCRIPTS (called by the Makefile)
│   │
│   ├── generate.sh                   # Generates machine configs. Creates secrets on
│   │                                 # first run. Combines base config + patches into
│   │                                 # a complete config file for each node.
│   │
│   ├── apply.sh                      # Pushes machine configs to the Talos nodes.
│   │                                 # Supports targeting specific nodes by hostname.
│   │                                 # Use --insecure for first-time setup.
│   │
│   ├── bootstrap.sh                  # Initializes the cluster (runs ONCE EVER).
│   │                                 # Starts etcd, waits for health, gets kubeconfig.
│   │
│   ├── upgrade.sh                    # Upgrades Talos on nodes one at a time.
│   │                                 # Safe order: workers first, then CP, bootstrap last.
│   │
│   ├── health.sh                     # Runs a comprehensive health check on the cluster.
│   │                                 # Checks Talos services, node versions, K8s status.
│   │
│   └── s3-sync.sh                    # Syncs secrets between the local .s3/ folder
│                                     # and the AWS S3 bucket. Supports push and pull.
│
├── .github/                          # CI/CD (GitHub Actions)
│   │
│   ├── workflows/
│   │   ├── validate.yaml             # Runs on every Pull Request. Lints scripts,
│   │   │                             # validates Talos configs, scans for leaked secrets.
│   │   │
│   │   ├── deploy.yaml               # Manual trigger. Applies configs or upgrades
│   │   │                             # nodes. Requires "production" environment approval.
│   │   │                             # REQUIRES a self-hosted runner on your network.
│   │   │
│   │   └── security.yaml             # Runs weekly + on PRs. Scans for secrets with
│   │                                 # gitleaks, audits config patches, checks version pins.
│   │
│   └── CODEOWNERS                    # Defines who must review changes to specific files.
│                                     # All changes to cluster/, scripts/, .github/ require
│                                     # review from @HellBomb.
│
├── .s3/                              # LOCAL SECRETS MIRROR (GITIGNORED - never committed!)
│   │                                 # This folder is your local copy of the S3 bucket.
│   │                                 # It contains everything sensitive:
│   │
│   ├── secrets/
│   │   └── secrets.yaml              # Talos secrets bundle (PKI certificates, tokens).
│   │                                 # This is the MOST IMPORTANT file. If you lose this
│   │                                 # AND the S3 backup, you must rebuild the cluster.
│   │
│   ├── configs/
│   │   ├── talosconfig               # Admin credential for talking to Talos API.
│   │   └── kubeconfig                # Admin credential for talking to Kubernetes API.
│   │
│   └── generated/                    # Final machine configs (contain embedded secrets).
│       ├── controlplane/
│       │   ├── cp1.yaml
│       │   ├── cp2.yaml
│       │   └── cp3.yaml
│       └── worker/
│           ├── w1.yaml
│           ├── w2.yaml
│           └── w3.yaml
│
├── Makefile                          # COMMAND ENTRY POINT. Every operation you perform
│                                     # goes through this file. Run "make help" to see
│                                     # all available commands.
│
├── .gitignore                        # Tells git which files to NEVER track. The .s3/
│                                     # folder and any secret files are listed here.
│
├── .editorconfig                     # Ensures consistent formatting (tabs vs spaces,
│                                     # line endings) across all editors.
│
├── .pre-commit-config.yaml           # Runs automatic checks before every git commit:
│                                     # - Scans for leaked secrets (gitleaks)
│                                     # - Lints shell scripts (shellcheck)
│                                     # - Checks for private keys, merge conflicts
│
├── CLAUDE.md                         # Context file for Claude AI assistant.
├── README.md                         # This file. You're reading it.
└── systems                           # Original reference file with node IP assignments.
```

### What is the `.s3/` Folder?

The `.s3/` folder is a **local mirror** of an AWS S3 bucket. It holds all the sensitive data — encryption keys, certificates, access tokens, and the final generated machine configs (which have secrets embedded in them).

**This folder is gitignored** — it is NEVER committed to the repository. If you look at the `.gitignore` file, you'll see `.s3/` listed there.

The workflow is:

1. You work locally — secrets live in `.s3/` on your machine
2. When you're done, run `make s3-push` to upload them to AWS S3 (encrypted)
3. If you're on a new machine, run `make s3-pull` to download them from AWS S3
4. In CI/CD, the pipeline pulls from S3 before running operations

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

You should see output like: `Talos v1.12.5`

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
    cp1 (10.69.112.63) → hostname: cp1
    cp2 (10.69.112.64) → hostname: cp2
    cp3 (10.69.112.65) → hostname: cp3
==> Generating per-node worker configs...
    w1 (10.69.112.68) → hostname: w1
    w2 (10.69.112.69) → hostname: w2
    w3 (10.69.112.70) → hostname: w3
==> Generation complete!
```

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

helm repo add cilium https://helm.cilium.io/
helm repo update

helm install cilium cilium/cilium \
    --version 1.16.6 \
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

Then install the auto-approver so you never have to do this manually again:

```bash
kubectl apply -f https://raw.githubusercontent.com/alex1989hu/kubelet-serving-cert-approver/main/deploy/standalone-install.yaml
```

### Step 10: Install Remaining Addons

Each command below installs one addon. Run them in order.

**Kubelet CSR Approver** (auto-approves kubelet serving-cert CSRs so kubelet's `rotate-server-certificates: true` setting works without manual `kubectl certificate approve`):

```bash
helm repo add postfinance https://postfinance.github.io/kubelet-csr-approver
helm repo update
helm install kubelet-csr-approver postfinance/kubelet-csr-approver \
    --version 1.2.14 \
    --namespace kube-system \
    -f addons/kubelet-csr-approver/values.yaml
```

Verify it landed and the controller acquired the leader lease:

```bash
kubectl -n kube-system get pods -l app.kubernetes.io/name=kubelet-csr-approver
kubectl -n kube-system logs -l app.kubernetes.io/name=kubelet-csr-approver --tail 5
```

You should see `Successfully acquired lease` and `Starting workers`. See [ADR-0005](docs/decision-records/repo/0005-kubelet-csr-approver.md).

**Metrics Server** (enables `kubectl top` to see CPU/memory usage):

```bash
helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server/
helm repo update
helm install metrics-server metrics-server/metrics-server \
    --namespace kube-system \
    -f addons/metrics-server/values.yaml
```

**Ingress NGINX** (routes incoming web traffic to your applications):

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

# Create and label the namespace (required for security policy)
kubectl create namespace ingress-nginx
kubectl label namespace ingress-nginx \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/audit=privileged \
    pod-security.kubernetes.io/warn=privileged

helm install ingress-nginx ingress-nginx/ingress-nginx \
    --namespace ingress-nginx \
    -f addons/ingress-nginx/values.yaml
```

**Local Path Provisioner** (provides storage for applications that need to save data):

```bash
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.30/deploy/local-path-storage.yaml

# Make it the default storage class
kubectl patch storageclass local-path -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

**Longhorn** (distributed block storage with replication; provides the cluster's default `StorageClass`):

```bash
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
    --version 1.11.1 \
    --namespace longhorn-system \
    -f addons/longhorn/values.yaml
```

The `values.yaml` makes `longhorn` the cluster's default `StorageClass` and sets `defaultDataPath: /var/mnt/longhorn` so Longhorn writes to the Talos `UserVolumeConfig` declared in `cluster/patches/volumes.yaml` (50–240 GiB carved out of every node's system disk). See [ADR-0007](docs/decision-records/repo/0007-capture-longhorn-as-managed-addon.md) for the rationale behind each non-default value.

> **Note on the local-path-provisioner step above:** The live cluster does NOT have local-path-provisioner installed; Longhorn is the only StorageClass. The local-path step is a vestige from earlier setup and should be considered optional. Removing it from this runbook is a follow-up.

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

### Step 12: Deploy the Proof of Concept

Deploy a simple web page that confirms the cluster is working:

```bash
kubectl apply -f addons/poc/
```

Wait 15 seconds, then test it:

```bash
curl http://10.69.112.68/
curl http://10.69.112.69/
curl http://10.69.112.70/
```

All worker nodes should return an HTML page containing "OPERATIONAL". You can also open `http://10.69.112.68` in a web browser.

### Step 13: Back Up Your Secrets

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

1. **Edit `cluster/config.env`** — add the new node to the `WORKER_NODES` line, using the next short-name ordinal (`w4`, `w5`, …) and recording the asset name in `systems`:

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

3. Remove the node from `WORKER_NODES` in `cluster/config.env` and delete `cluster/patches/w2.yaml`.

4. Power off or repurpose the physical machine.

### Recovering Secrets on a New Machine

If you're setting up on a new computer (or your `.s3/` folder was lost):

```bash
make s3-pull
```

This downloads all secrets from the AWS S3 bucket. You then have full access to manage the cluster.

### Disaster Recovery — Restoring etcd from a Snapshot

The `etcd Snapshot` workflow (`.github/workflows/etcd-snapshot.yaml`) uploads a
daily snapshot to S3. If the cluster's etcd quorum is lost (two CPs broken
simultaneously, etcd corruption that propagates, etc.), restore via the
following sequence. See [ADR-0006](docs/decision-records/repo/0006-etcd-snapshot-automation.md) for the
decision context.

#### 1. Find the snapshot you want to restore from

```bash
aws s3 ls s3://793496711039-terraform/nwarila-platform/talos-cluster/etcd-snapshots/ --recursive | tail
```

Pick the most recent snapshot whose timestamp pre-dates the incident.

#### 2. Pull the snapshot locally

```bash
mkdir -p .s3/restore
aws s3 cp \
  s3://793496711039-terraform/nwarila-platform/talos-cluster/etcd-snapshots/YYYY-MM-DD/snapshot-HHMMSSZ.db \
  .s3/restore/snapshot.db
```

#### 3. Wipe the CP nodes (Talos requires a clean state for `--recover-from`)

```bash
# For EACH control-plane node — applies in safe order (cp1 last as bootstrap)
talosctl reset --talosconfig .s3/configs/talosconfig --nodes 10.69.112.64 --graceful=false --reboot
talosctl reset --talosconfig .s3/configs/talosconfig --nodes 10.69.112.65 --graceful=false --reboot
talosctl reset --talosconfig .s3/configs/talosconfig --nodes 10.69.112.63 --graceful=false --reboot
```

> **WARNING:** This wipes the system disks on the CP nodes. Only run if the
> cluster is already unrecoverable. If you're testing recovery, do it on a
> sacrificial cluster, not production.

#### 4. Reapply machine configs to the wiped CPs

```bash
make apply-insecure NODES="cp1 cp2 cp3"
```

#### 5. Bootstrap a CP with the snapshot

```bash
talosctl bootstrap \
  --talosconfig .s3/configs/talosconfig \
  --nodes 10.69.112.63 \
  --recover-from .s3/restore/snapshot.db
```

#### 6. Wait for the cluster to come back

```bash
make health
kubectl get nodes
```

The worker nodes' kubelets will re-attach to the recovered control plane on
their next health check. Workloads referenced in the snapshot (Deployments,
DaemonSets, StatefulSets, Helm releases tracked via Helm 3 Secrets) come back
as etcd is repopulated.

#### 7. Re-run drift detection to confirm repo and recovered state match

```bash
bash scripts/drift-check.sh
```

Any drift the workflow surfaces is something the snapshot didn't carry — for
example, a Talos machine-config change that was made between the snapshot and
the incident. Decide whether to reapply via `make apply` (preferred) or to
accept the recovered state and back-port to the repo.

> **Note:** Restore from snapshot has not yet been drilled against this
> cluster. A follow-up cycle will run the drill against a sacrificial cluster
> and document the result as ADR-0007. Until then, the snapshots are a
> recovery primitive whose viability is **not formally verified**.

### Deploying Your Own Application

1. Create a YAML file describing your application (a Deployment, Service, and optionally an Ingress).
2. Apply it:

   ```bash
   kubectl apply -f my-app.yaml
   ```

3. Check that it's running:

   ```bash
   kubectl get pods
   ```

For a simple example, look at the files in `addons/poc/`.

---

## CI/CD (Automated Pipelines)

Three GitHub Actions workflows are configured:

### Validate (runs on every Pull Request)

**Trigger:** Any PR to `main` that changes files in `cluster/`, `scripts/`, or `Makefile`.

**What it does:**

1. **Lints shell scripts** with ShellCheck (catches common scripting mistakes)
2. **Lints YAML files** with yamllint (catches formatting issues)
3. **Generates throwaway configs** and validates them with `talosctl validate`
4. **Scans for leaked secrets** in the code (private keys, tokens, etc.)

### Deploy (manual trigger only)

**Trigger:** You manually click "Run workflow" in the GitHub Actions UI.

**What it does:**

1. Pulls secrets from S3
2. Generates and validates configs
3. Applies configs or performs upgrades (your choice)
4. Runs health checks

**Requirements:**

- A **self-hosted GitHub Actions runner** on a machine that has network access to the Talos nodes (10.69.112.0/24 network). GitHub's cloud runners cannot reach your private network.
- The `production` environment must be configured in GitHub with required reviewers for approval.

### Security Audit (weekly + on PRs)

**Trigger:** Every Monday at 6:00 AM UTC, and on every PR to `main`.

**What it does:**

1. **Gitleaks scan** — searches the entire git history for accidentally committed secrets
2. **Config audit** — checks that no secrets are in patch files, VIP is consistent, versions are pinned (not "latest"), and every node has a patch file

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

**Cause:** Kubelet serving certificates haven't been approved.

**Fix:**

```bash
kubectl get csr | grep Pending | awk '{print $1}' | xargs kubectl certificate approve
```

Then delete the metrics-server pod so it restarts:

```bash
kubectl delete pod -n kube-system -l app.kubernetes.io/name=metrics-server
```

### ingress-nginx pods not starting (PodSecurity violation)

**Cause:** The `ingress-nginx` namespace doesn't have the `privileged` PodSecurity label.

**Fix:**

```bash
kubectl label namespace ingress-nginx \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/audit=privileged \
    pod-security.kubernetes.io/warn=privileged \
    --overwrite
kubectl rollout restart daemonset ingress-nginx-controller -n ingress-nginx
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
