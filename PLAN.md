# talos-cluster Build Plan v2

This document supersedes the earlier build plan as the authoritative project plan for `nwarila-platform/talos-cluster`.

The goal is not to simulate a regulated enterprise. The goal is to build a serious, security-conscious Talos platform in public, with decisions that are credible, reproducible, and proportional to the actual project.

The main design correction in this revision is simple: keep the controls that defend real failure modes, and remove the AWS and workflow complexity that exists only to prove that we know it exists.

---

## 1. Architectural Decisions

### 1.1 Target Topology — APPROVED

- **Hardware**: 6 bare-metal Intel NUCs
- **Split**: 3 control plane + 3 workers
- **Rationale**: 3 control-plane nodes preserve etcd quorum and tolerate one control-plane failure. 3 workers give enough spread for platform services plus tenant workloads.
- **Current state**: 4 nodes are currently online (`cp1`, `cp3`, `w2`, `w3`). Two additional nodes are installed but currently blocked by a Talos UEFI boot-entry issue. The cluster will be rebuilt to the intended 3+3 topology as part of bootstrap.

### 1.2 Repository Name — APPROVED

- **Repo**: `nwarila-platform/talos-cluster`
- **Rationale**: It accurately describes the repository as the cluster platform definition. The existing external runner naming can remain unchanged.

### 1.3 Repository Split — APPROVED

- **Core** (inside `talos-cluster`): Cilium, cert-manager, external-dns, External Secrets Operator, Vault, ArgoCD, Longhorn, cloudflared.
- **Extended** (separate repos, discovered by `platform-*` ApplicationSet): `platform-monitoring`, `platform-backup`, `platform-policy`, `platform-security`.
- **Tenant** (separate repos, discovered by `deploy-*` ApplicationSet): application repos that satisfy the platform admission contract.
- **Rationale**: Core services are tightly coupled to cluster bootstrap and should evolve together. Extended and tenant workloads should be independently maintainable. This is the cleanest hybrid monorepo/polyrepo split for the project.

### 1.4 Domain Layout — APPROVED

- **Apex**: `nickwarila.com` (main website remains outside this cluster)
- **Cluster services**: flat subdomains of the apex (`grafana.nickwarila.com`, `argocd.nickwarila.com`, `api.nickwarila.com`)
- **DNS safety**: separate scoped Cloudflare tokens for cert-manager and external-dns; external-dns runs `upsert-only` with TXT ownership records.

### 1.5 Secret Architecture — APPROVED

- **Tier 1 — GitHub Actions / environment secrets**: only the provider or bootstrap credentials that cannot use OIDC. AWS uses OIDC, not static AWS access keys.
- **Tier 2 — Vault**: runtime secrets consumed by in-cluster workloads.
- **Rationale**: Vault remains cluster-internal and should not be made reachable from CI. GitHub-hosted automation therefore needs its own narrow credential surface for non-AWS providers, while AWS authentication should use short-lived OIDC credentials.
- **Vault unseal**: AWS KMS auto-unseal via a dedicated runtime IAM identity created by bootstrap Terraform.

### 1.6 External Access — APPROVED

- **Public services**: DDNS → ISP public IP → pfSense HAProxy (HA pair) → Cilium LoadBalancer VIP → public Gateway → HTTPRoutes
- **Private services**: Cloudflare Tunnel + mTLS → cloudflared → private Gateway → HTTPRoutes
- **Gateway split**: `public-gateway` for public services, `private-gateway` for admin and sensitive surfaces.

### 1.7 Cilium Load Balancer Advertisement — APPROVED

- **Method**: BGP peering (Cilium BGP Control Plane ↔ pfSense FRR)
- **Rationale**: Clean routing semantics, good resume signal, and a realistic edge pattern for a homelab with HA routers.

### 1.8 Email / Alerting — APPROVED

- **Provider**: Resend
- **Rationale**: clean API, low complexity, sufficient scale for platform notifications.

---

## 2. AWS, GitHub Actions, and Repository Security Model

### 2.1 Guiding Principles — APPROVED

1. The repository is intentionally public.
2. Public pull requests are untrusted by default.
3. Bootstrap and platform remain separate Terraform states.
4. Destruction is a separate manual path.
5. AWS access starts only at trusted entrypoints.
6. Runtime cloud identities remain declarative and Terraform-managed.
7. The plan must stay legible enough that a reviewer can understand it in one sitting.

This project is not trying to showcase every advanced IAM pattern. It is trying to showcase sound judgment.

### 2.2 Terraform Layout — APPROVED

```text
terraform/
├── bootstrap/               # Sensitive foundation resources
│   ├── versions.tf
│   ├── providers.tf
│   ├── backend.tf           # bootstrap.tfstate
│   ├── kms.tf               # Vault unseal key + alerts
│   ├── iam.tf               # vault-unseal and velero runtime identities
│   ├── s3.tf                # Velero backup bucket
│   ├── events.tf            # EventBridge/SNS alarm wiring
│   └── outputs.tf
│
└── platform/                # Day-2 platform resources
    ├── versions.tf
    ├── providers.tf
    ├── backend.tf           # platform.tfstate
    ├── data.tf              # remote-state inputs from bootstrap
    ├── cloudflare.tf
    ├── github.tf
    ├── vault_seed.tf
    └── outputs.tf
```

### 2.3 Trust Zones — APPROVED

There are only two trust zones.

#### Zone A: public-safe PR CI

Used on `pull_request`.

It does:

- `terraform fmt -check -recursive`
- `terraform init -backend=false`
- `terraform validate`
- YAML and workflow linting (`actionlint`, optionally `yamllint`)
- optional static Terraform linting (`tflint`) once configured

It does **not**:

- request OIDC tokens
- assume AWS roles
- read remote state
- use GitHub environments for secrets
- upload Terraform plan artifacts
- use `pull_request_target`
- run on self-hosted runners

#### Zone B: trusted deploy workflows

Used only for:

- `push` to `main`
- `workflow_dispatch` runs that validate `refs/heads/main`

These workflows may:

- assume AWS roles via OIDC
- read remote state
- use GitHub environments
- read environment-scoped secrets
- run Terraform against real infrastructure

### 2.4 Final Role and Identity Model — APPROVED

This plan keeps the bootstrap role split and simplifies the platform side.

| Identity | Type | Purpose | Trigger path | Notes |
|---|---|---|---|---|
| `github_nwarila-platform_talos-cluster_bootstrap_plan` | IAM role | Read-only bootstrap plan and destroy-plan | manual bootstrap workflows | shared plan role; can read state, lock, and write private plan artifacts |
| `github_nwarila-platform_talos-cluster_bootstrap_apply` | IAM role | Bootstrap create/update | manual bootstrap apply | environment-gated |
| `github_nwarila-platform_talos-cluster_bootstrap_destroy` | IAM role | Bootstrap destroy only | manual destroy workflow | separate trust, separate gate, wait timer |
| `github_nwarila-platform_talos-cluster_platform_apply` | IAM role | Platform apply on trusted `main` runs | push to `main` only | no PR cloud access; no separate platform plan role |
| `talos-cluster-vault-unseal` | IAM user | Vault auto-unseal at runtime | in-cluster only | created by bootstrap Terraform |
| `talos-cluster-velero` | IAM user | Velero backup/restore at runtime | in-cluster only | created by bootstrap Terraform |

Explicit simplifications:

- no `platform_plan` role
- no cloud-backed PR plan role
- no reusable-workflow trust lattice
- no manual runtime IAM identities outside Terraform

### 2.5 GitHub Environment Model — APPROVED

Create these environments before merging privileged workflows.

| Environment | Purpose | Required reviewer | Wait timer | Branch restriction | Notes |
|---|---|---|---:|---|---|
| `bootstrap-plan` | bootstrap and destroy planning | none | 0 | `main` only | no secrets, no approval |
| `bootstrap` | bootstrap create/update | `NWarila` | 0 | `main` only | human gate for sensitive mutation |
| `bootstrap-destroy` | bootstrap destroy | `NWarila` | 15 min | `main` only | explicit cooling-off period |
| `platform-apply` | trusted platform apply | none | 0 | `main` only | used for secret scoping, not human approval |

Notes:

- `Prevent self-review` stays disabled in solo mode.
- `Allow administrators to bypass` stays disabled everywhere.
- `platform-apply` exists to scope secrets and the OIDC claim, not to add ceremony to every normal platform merge.

### 2.6 Workflow Model — APPROVED

Create exactly these workflow files.

| File | Trigger | Cloud access | Purpose |
|---|---|---:|---|
| `.github/workflows/terraform-static-ci.yml` | `pull_request` | No | public-safe required check |
| `.github/workflows/terraform-platform-apply.yml` | `push` to `main` on `terraform/platform/**` | Yes | trusted platform plan+apply |
| `.github/workflows/terraform-bootstrap.yml` | `workflow_dispatch` | Yes | manual bootstrap plan/apply |
| `.github/workflows/terraform-bootstrap-destroy.yml` | `workflow_dispatch` | Yes | manual destroy path |

#### `terraform-static-ci.yml`

Required check for all pull requests.

Expected jobs:

- workflow lint (`actionlint`)
- Terraform format check
- `terraform init -backend=false`
- `terraform validate` for both `terraform/bootstrap` and `terraform/platform`

#### `terraform-platform-apply.yml`

Trusted workflow for routine day-2 operations.

Design:

- trigger only on `push` to `main`
- optional path filter: `terraform/platform/**`
- references `platform-apply` environment
- assumes only `..._platform_apply`
- runs `terraform plan -out=tfplan` and `terraform apply tfplan` within the same trusted run
- does **not** upload plan artifacts anywhere
- prints only a sanitized summary to public logs

This is the first trusted cloud boundary for platform changes. The PR itself remains static-only.

#### `terraform-bootstrap.yml`

Manual workflow for bootstrap planning and apply.

Design:

- `workflow_dispatch` only
- validates `github.ref == 'refs/heads/main'`
- `plan` job uses `..._bootstrap_plan` and `bootstrap-plan`
- `apply` job uses `..._bootstrap_apply` and `bootstrap`
- bootstrap plan artifacts are stored privately in S3 and fetched by exact version ID for apply
- public logs show only a sanitized summary

#### `terraform-bootstrap-destroy.yml`

Dedicated destroy workflow.

Design:

- `workflow_dispatch` only
- exact confirmation string required
- validates `github.ref == 'refs/heads/main'`
- destroy-plan job uses `..._bootstrap_plan`
- destroy job uses `..._bootstrap_destroy`
- environment `bootstrap-destroy` adds reviewer approval and a 15-minute wait timer
- exact destroy plan is stored privately in S3 and fetched by version ID

### 2.7 Policy Inventory — APPROVED

The build plan defines the policy inventory and intent. Exact JSON belongs in `iam/policies/` and the IAM implementation notes.

| Policy | Attached to | Purpose |
|---|---|---|
| `github_nwarila-platform_talos-cluster_bootstrap-plan` | `..._bootstrap_plan` | read bootstrap state, manage lockfile, write private plan objects, read resource metadata |
| `github_nwarila-platform_talos-cluster_bootstrap-state` | `..._bootstrap_apply`, `..._bootstrap_destroy` | bootstrap state read/write with encryption enforcement and state-file delete protection |
| `github_nwarila-platform_talos-cluster_bootstrap-kms` | `..._bootstrap_apply`, `..._bootstrap_destroy` | create/manage only the Vault unseal key and alias |
| `github_nwarila-platform_talos-cluster_bootstrap-runtime-iam` | `..._bootstrap_apply`, `..._bootstrap_destroy` | manage exactly two runtime IAM users and their exact policies |
| `github_nwarila-platform_talos-cluster_bootstrap-s3-backup` | `..._bootstrap_apply`, `..._bootstrap_destroy` | manage only the Velero backup bucket lifecycle |
| `github_nwarila-platform_talos-cluster_bootstrap-events` | `..._bootstrap_apply`, `..._bootstrap_destroy` | manage EventBridge and SNS alerting for KMS safety events |
| `github_nwarila-platform_talos-cluster_plan-artifact-read` | `..._bootstrap_apply`, `..._bootstrap_destroy` | read bootstrap plan objects from the private S3 backend bucket |
| `github_nwarila-platform_talos-cluster_platform-apply` | `..._platform_apply` | manage platform resources and state; read bootstrap outputs as needed |
| `talos-cluster-vault-unseal` policy | `talos-cluster-vault-unseal` user | exact KMS `Encrypt`, `Decrypt`, `DescribeKey` on the unseal key |
| `talos-cluster-velero-backup` policy | `talos-cluster-velero` user | exact S3 object and bucket access on the Velero bucket |

Important simplification:

- `bootstrap-runtime-iam` manages only the two named IAM **users** and their policies.
- It does **not** manage IAM roles, wildcard IAM resources, or future IRSA placeholders.
- IRSA or self-hosted OIDC is a future migration path, not a day-one requirement.

Critical scoping rule for `bootstrap-runtime-iam`:

- Use Terraform `aws_iam_user_policy` (inline policies) for the runtime users, not `aws_iam_user_policy_attachment` (managed policy attachment).
- The IAM management policy therefore needs `iam:PutUserPolicy`, `iam:DeleteUserPolicy`, `iam:GetUserPolicy`, and `iam:ListUserPolicies` -- but does **not** need `iam:AttachUserPolicy` or `iam:DetachUserPolicy`.
- This eliminates the privilege escalation vector where a compromised bootstrap role could call `AttachUserPolicy` to attach `arn:aws:iam::aws:policy/AdministratorAccess` to one of the runtime users, then mint fresh access keys via `CreateAccessKey`, achieving full account compromise through the scoped user ARNs.
- If managed policy attachment is preferred instead, scope `AttachUserPolicy` with an `iam:PolicyArn` condition restricting it to the two exact customer-managed policy ARNs. Never allow unrestricted `AttachUserPolicy` on any user ARN.

Carry-forward requirements from prior audits (apply when writing policy JSON):

- `bootstrap-plan` and `platform-apply` must include dual encryption denies (`StringNotEquals` + `Null` on `s3:x-amz-server-side-encryption`) scoped to the full `nwarila-platform/talos-cluster/*` prefix, not just per-path.
- `platform-apply` must include an explicit `Deny` on `s3:PutObject` and `s3:DeleteObject` against `bootstrap.tfstate`. IAM default-deny is not sufficient -- an explicit deny survives future policy additions.
- `bootstrap-kms` must include the `DenyTagLaundering`, `kms:KeySpec`/`kms:KeyUsage` conditions, and exact alias scoping from the earlier KMS audit.

### 2.8 Trust Policy Rules — APPROVED

Use exact-match trust wherever practical.

#### `bootstrap_plan`

Trust conditions:

- `aud = sts.amazonaws.com`
- exact repository ID
- `ref = refs/heads/main`
- `environment = bootstrap-plan`
- exact `sub` for `environment:bootstrap-plan`

`workflow` pinning is not required on this shared read-only plan role.

#### `bootstrap_apply`

Trust conditions:

- `aud = sts.amazonaws.com`
- exact repository ID
- `ref = refs/heads/main`
- `environment = bootstrap`
- exact `workflow = Terraform Bootstrap`
- exact `sub` for `environment:bootstrap`

#### `bootstrap_destroy`

Trust conditions:

- all bootstrap-apply conditions, but with `environment = bootstrap-destroy`
- exact `workflow = Terraform Bootstrap Destroy`
- exact numeric `actor_id` for the operator

#### `platform_apply`

Trust conditions:

- `aud = sts.amazonaws.com`
- exact repository ID
- `ref = refs/heads/main`
- `environment = platform-apply`
- exact `workflow = Terraform Platform Apply`
- exact `sub` for `environment:platform-apply`

### 2.9 Runtime IAM Identities — APPROVED

This plan restores runtime identities to Terraform ownership, but in a narrower and cleaner form than the earlier draft.

#### `talos-cluster-vault-unseal`

- IAM user created by bootstrap Terraform
- one customer-managed policy attached
- permissions limited to `kms:Encrypt`, `kms:Decrypt`, and `kms:DescribeKey` on the exact Vault unseal key ARN
- access keys stored via the bootstrap secret path and then seeded into Vault / Kubernetes as required

#### `talos-cluster-velero`

- IAM user created by bootstrap Terraform
- one customer-managed policy attached
- permissions limited to the exact Velero backup bucket
- no bucket lifecycle or KMS permissions

Why this is the right middle ground:

- declarative and reproducible
- tighter than manually managed users
- materially simpler than pretending IRSA is available on day one

### 2.10 Plan Storage and Logging — APPROVED

#### Bootstrap and destroy

- save binary plans privately in the existing Terraform S3 backend bucket
- fetch by exact S3 version ID for apply / destroy
- do not upload plans to GitHub artifacts
- do not print full plan output to GitHub logs

#### Platform day-2 apply

- do not persist plan artifacts
- run `plan -out=tfplan` and `apply tfplan` inside the same trusted run
- write only sanitized summaries to `$GITHUB_STEP_SUMMARY`

This is the cleanest balance:

- exact reviewed plan handoff where there is a real approval boundary
- no extra artifact machinery where there is not

### 2.11 Defense in Depth — APPROVED

These controls remain because they defend real failure modes.

1. **OIDC only for AWS in GitHub Actions**
   - no long-lived AWS keys in GitHub

2. **KMS resource policy deny-by-default**
   - only account root, bootstrap management roles, and Vault runtime identity can use the unseal key

3. **`prevent_destroy` on high-impact bootstrap resources**
   - Vault unseal key
   - runtime IAM users
   - Velero backup bucket

4. **EventBridge + SNS alert on destructive KMS operations**
   - `ScheduleKeyDeletion`
   - `DisableKey`
   - `PutKeyPolicy`

5. **30-day KMS deletion window**
   - maximum AWS pending-deletion window for recovery time

6. **S3 versioning on the Terraform backend bucket**
   - protects state and bootstrap plan objects against accidental overwrite or deletion

7. **SHA-pinned GitHub Actions**
   - no mutable tags in privileged workflows

8. **Restricted `GITHUB_TOKEN` by default**
   - grant higher permissions per job only when required

9. **Public-repo runner hygiene**
   - GitHub-hosted runners only for public PR workflows
   - no `pull_request_target` for Terraform or deployment logic

### 2.12 Approval Chains — APPROVED

#### Normal platform change

1. Open PR
2. `terraform-static-ci` passes
3. Resolve review comments
4. Merge to `main`
5. `Terraform Platform Apply` runs on trusted `main`
6. Workflow plans and applies within the same run using `..._platform_apply`

#### Bootstrap create/update

1. Open PR
2. `terraform-static-ci` passes
3. Merge to `main`
4. Manually run `Terraform Bootstrap`
5. Workflow validates `main`
6. `bootstrap-plan` job runs with `..._bootstrap_plan`
7. If `apply` was requested, exact plan is stored in S3
8. Approve `bootstrap` environment
9. `bootstrap-apply` downloads the exact plan and applies with `..._bootstrap_apply`

#### Bootstrap destroy

1. Submit PR that intentionally removes or relaxes `prevent_destroy` only where necessary
2. `terraform-static-ci` passes
3. Merge to `main`
4. Manually run `Terraform Bootstrap Destroy`
5. Type the exact confirmation string
6. Workflow validates `main`
7. `bootstrap-destroy-plan` runs with `..._bootstrap_plan`
8. Exact destroy plan is stored in S3
9. Approve `bootstrap-destroy` environment
10. 15-minute wait timer runs
11. `bootstrap-destroy` downloads the exact plan and applies with `..._bootstrap_destroy`
12. If KMS deletion is involved, the 30-day pending-deletion window and alerting controls take over

### 2.13 Patterns Explicitly Not Adopted — APPROVED

These are intentionally out of scope.

- cloud-authenticated PR plan role for platform
- separate `platform_plan` role
- S3 plan handoff for routine platform apply
- reusable-workflow OIDC trust lattice via `job_workflow_ref`
- private GitHub repository requirement
- AWS Organizations / SCPs
- dedicated security account
- CloudHSM / HSM-backed keys
- two-person approval theatre in a solo-operator repo
- `pull_request_target` deployment logic
- self-hosted runners for public PR workflows
- day-one IRSA or self-hosted Kubernetes OIDC provider

---

## 3. Repository Controls

### 3.1 Branch Protection — APPROVED

Protect `main` with:

- pull requests required
- required status checks required
- required check: `terraform-static-ci`
- conversation resolution required
- no bypass
- force pushes disabled
- deletions disabled
- only `NWarila` may push to matching branches

Solo-operator honesty:

- do **not** require PR approvals until a second reviewer exists
- do **not** describe CODEOWNERS as a real merge gate yet

### 3.2 CODEOWNERS — APPROVED

Create:

```text
/.github/ @NWarila
/terraform/ @NWarila
/docs/ @NWarila
```

Purpose:

- documents ownership
- auto-requests review
- scales cleanly if collaborators are added later

### 3.3 GitHub Actions Settings — APPROVED

Repository settings should reflect the public-repo threat model.

- default `GITHUB_TOKEN`: read-only
- require approval for workflows from all external contributors
- allow only the actions actually used
- pin all privileged actions to full commit SHAs
- enable GitHub-native security features available for public repos: secret scanning, push protection, dependency graph, Dependabot, dependency review, code scanning

---

## 4. Phase Plan

### Phase 0 — Repo Foundation

Deliverables:

- Taskfile / Makefile entrypoints
- devcontainer
- pre-commit
- Renovate
- SOPS config
- editor and linting baseline
- README skeleton

### Phase 1 — Terraform Foundation and AWS Controls

Deliverables:

- `terraform/bootstrap` and `terraform/platform` skeletons
- backend and provider configuration
- four IAM identities / roles from this plan
- two runtime IAM users created by bootstrap Terraform
- KMS key, backup bucket, and alerting resources
- GitHub environments and branch protection
- four workflow files from §2.6

Definition of done:

- `terraform-static-ci` passes on PRs
- manual bootstrap plan succeeds
- platform apply workflow is wired and trusted to `main`

### Phase 2 — Talos Configuration

Deliverables:

- `talconfig.yaml`
- schematic configuration
- machine patches
- inventory and node role mapping
- documented rebuild procedure for the current 4-node interim state to the intended 6-node topology

### Phase 3 — Core Platform Services

Deliverables:

- Cilium
- cert-manager
- external-dns
- Vault
- External Secrets Operator
- Longhorn
- cloudflared

### Phase 4 — GitOps Bootstrap

Deliverables:

- ArgoCD bootstrap
- AppProjects
- ApplicationSets for core, platform, and tenant repos
- public and private gateways / routes

### Phase 5 — Operations, Recovery, and Security Docs

Deliverables:

- architecture docs
- bootstrap docs
- upgrade docs
- recovery docs
- security docs
- break-glass procedure for destroy-role `actor_id` updates
- backup and restore runbooks

### Phase 6 — Extended Platform Repos

Deliverables:

- `platform-monitoring`
- `platform-backup`
- `platform-policy`
- `platform-security`

---

## 5. Immediate Execution Plan

This is the shortest path to meaningful progress.

### Today

1. Create the repository scaffolding from Phase 0.
2. Commit the `terraform/bootstrap` and `terraform/platform` directory skeletons.
3. Create the GitHub environments:
   - `bootstrap-plan`
   - `bootstrap`
   - `bootstrap-destroy`
   - `platform-apply`
4. Apply branch protection and GitHub Actions settings.
5. Create the four IAM roles and the two runtime IAM policy documents in `iam/policies/`.
6. Add the four workflow files from §2.6.
7. Open a PR and get `terraform-static-ci` green.
8. Merge to `main`.
9. Run `Terraform Bootstrap` in `plan` mode successfully.

### Next working session

1. Finish the bootstrap Terraform resources:
   - KMS key
   - runtime IAM users
   - Velero bucket
   - EventBridge / SNS alerting
2. Run bootstrap apply.
3. Wire `terraform/platform` to consume bootstrap outputs.
4. Validate that platform apply can run on `main` without exposing secrets or plan output publicly.
5. Start Talos configuration work.

### What counts as meaningful progress by end of day

All of the following should be true:

- repository controls are in place
- Terraform skeleton exists
- workflows exist
- IAM role model is settled
- public PR CI passes
- bootstrap manual plan works

If those are done, the project is moving. Do not burn the day building every downstream service before the platform contract is stable.

---

## 6. Files and Directories to Create First

```text
.github/
├── CODEOWNERS
└── workflows/
    ├── terraform-static-ci.yml
    ├── terraform-platform-apply.yml
    ├── terraform-bootstrap.yml
    └── terraform-bootstrap-destroy.yml

terraform/
├── bootstrap/
│   ├── backend.tf
│   ├── providers.tf
│   ├── versions.tf
│   ├── kms.tf
│   ├── iam.tf
│   ├── s3.tf
│   ├── events.tf
│   └── outputs.tf
└── platform/
    ├── backend.tf
    ├── providers.tf
    ├── versions.tf
    ├── data.tf
    ├── cloudflare.tf
    ├── github.tf
    ├── vault_seed.tf
    └── outputs.tf

iam/
├── policies/
│   ├── bootstrap-plan.json
│   ├── bootstrap-state.json
│   ├── bootstrap-kms.json
│   ├── bootstrap-runtime-iam.json
│   ├── bootstrap-s3-backup.json
│   ├── bootstrap-events.json
│   ├── plan-artifact-read.json
│   ├── platform-apply.json
│   ├── runtime-vault-unseal.json
│   └── runtime-velero-backup.json
└── trust/
    ├── bootstrap-plan-trust.json
    ├── bootstrap-apply-trust.json
    ├── bootstrap-destroy-trust.json
    └── platform-apply-trust.json

docs/
├── architecture.md
├── bootstrap.md
├── recovery.md
├── security.md
└── adr/
```

---

## 7. Final Decision Summary

The project now uses a smaller and cleaner AWS model:

- keep bootstrap/platform state separation
- keep a shared read-only bootstrap plan role
- keep separate bootstrap apply and destroy roles
- keep destroy as a dedicated manual workflow
- keep runtime IAM identities declarative in Terraform
- keep platform PR CI public-safe and non-privileged
- start trusted cloud execution only on `main` or manual bootstrap workflows
- avoid platform role and artifact complexity that does not buy meaningful risk reduction

That is the right level of engineering for this repository.
