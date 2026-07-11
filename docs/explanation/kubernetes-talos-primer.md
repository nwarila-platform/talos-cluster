# Kubernetes And Talos Primer

Back to the [README](../../README.md).

## What Is This?

This repository contains everything needed to deploy, manage, and operate a **Kubernetes cluster** running on **TalosOS**.

Here's what those terms mean in plain language:

- **Kubernetes** is a system that runs applications inside lightweight packages called "containers." Instead of installing software directly on a computer, you put it in a container that can run anywhere. Kubernetes manages many of these containers across multiple computers, making sure they stay running, can handle traffic, and recover from failures.

- **TalosOS** is the operating system installed on each computer (called a "node") in the cluster. Unlike a conventional server OS, TalosOS is *immutable* — you cannot SSH into it, you cannot install software on it, and you cannot change files on it. It is managed entirely through an API (a programmatic interface). This makes it extremely secure and consistent. If a node has a problem, you don't debug it — you replace it.

- **A cluster** is a group of computers working together as one. Ours has 6 physical machines (nodes).

This repository is the rebuild source for the cluster. Machine-readable node endpoints, role partition, VIP, bootstrap node, and version pins live in `cluster/config.env`; the human asset table lives in `systems`; and their overlapping fields are checked in CI. If the cluster were to be destroyed, this repo (plus the secrets stored in S3) is the material needed to rebuild it from scratch.

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

Use `systems` for the human node inventory and `cluster/config.env` for machine-readable node endpoints, role partition, VIP, and bootstrap data. [ADR-0002](../decision-records/repo/0002-use-short-talos-hostnames.md) explains the short hostname convention.

When you run a command like `kubectl apply -f my-app.yaml`, here's what happens:

1. Your command goes to the VIP (10.69.112.62)
2. The active control plane node receives it
3. Kubernetes decides which worker node should run your app
4. The worker node downloads and starts the container
5. Your app is now running and accessible
