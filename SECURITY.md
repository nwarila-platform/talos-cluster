# Security Policy

## Reporting a vulnerability

Please report suspected security vulnerabilities through GitHub's **private vulnerability reporting**:

> Repository **Security** tab → **Report a vulnerability**
> (<https://github.com/nwarila-platform/talos-cluster/security/advisories/new>)

Private reporting keeps the report confidential while a fix is coordinated. **Do not open a public
issue** for a suspected vulnerability.

Please include, where possible: the affected file/manifest/workflow, the impact, and steps or a
proof-of-concept to reproduce.

## Scope and context

This is a personal homelab and **portfolio** GitOps repository for a real Talos Kubernetes platform.
It is **deliberately public**, including its internal network topology (RFC 1918 addresses, VLANs,
node inventory, storage targets). That exposure is an intentional portfolio decision with an accepted
threat model — see the transparency note in the repository — and would not be appropriate for a
production system operated for others. Reports that amount to "you published private-range IPs" are
therefore known and accepted, not vulnerabilities.

In scope for reports:

- Secrets or credentials committed to git in a way that grants real access (the repo uses SOPS/age
  encryption and a deny-all `.gitignore`; a genuine plaintext-secret leak is in scope).
- Errors in the security controls themselves — Kyverno policies, the CI boundary guards, RBAC,
  network policies, admission/supply-chain rules — that would let an untrusted input bypass a stated
  control.
- CI/CD or supply-chain weaknesses (workflow injection, unpinned or spoofable actions, signature
  verification gaps).

## What to expect

- An acknowledgement that the report was received.
- An honest assessment of whether it is in scope and, if so, a coordinated fix tracked in git.
- Credit in the fix's commit or advisory if you would like it.

There is no bug-bounty program; this is a personal project maintained on a best-effort basis.
