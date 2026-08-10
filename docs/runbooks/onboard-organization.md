# Runbook: onboard a new GitHub organization to the source-token minting chain

**Scope.** Adding a *new GitHub organization* whose `deploy-*` repositories should become
tenants. This is NOT the per-tenant path — a new repo inside an already-onboarded org
needs only an `orgPrefix` registration (see [ADR-0011](../decision-records/repo/0011-auto-discover-deploy-repositories.md)
and `cluster/deploy-repo-overrides.sh`). Use this runbook once per *organization*.

**Why a runbook exists.** Onboarding `nwp` (`nwarila-platform`) required nine coordinated
edits across Vault ACL policy, Kubernetes auth roles, cluster RBAC, a CronJob, a Kyverno
protection policy, a CI guard's pinned-consumer table, `.gitignore`, and two documents.
Four of those had no automated check and would have failed silently — see
**Failure modes** below. Follow the list; do not reconstruct it from memory.

---

## What actually prevents an org from acting as another org

Worth understanding before you change anything here, because it is easy to over-engineer
against the wrong threat.

The per-org rotators share ONE minter script; only environment variables distinguish them.
That looks fragile, and an earlier attempt at a CI guard tried to police the script's source
for hardcoded organizations. That guard was withdrawn: it was bypassable in many ways and it
rejected legitimate code, and — the deciding point — it defended a door that is already
bolted:

1. **Vault's Kubernetes-auth role binds an exact ServiceAccount name.**
   `bound_service_account_names: ["source-rotator-<prefix>"]` is checked against the pod's
   projected ServiceAccount token via TokenReview. A pod running as another org's SA simply
   cannot log in with this role, whatever its `VAULT_ROLE` env says. A pod cannot forge this.
2. **The role's policy scopes the App key.** `policy-source-minter-<prefix>` grants read on
   `secret/data/platform/org-pull/<prefix>/gitops-source-auth` and nothing else, so even a
   successful login cannot read another org's GitHub App key.
3. **A GitHub App installation only covers its own org's repositories.** Even holding an App
   key, you cannot mint a token for a repo outside that installation.

Those three controls are **not equally strong, and the difference matters**:

| Variable | Wrong value is caught by | Strength |
|---|---|---|
| `VAULT_ROLE` | Vault TokenReview against the bound SA name | **structural** — cannot be forged from the pod |
| `VAULT_KEY_PATH` | the authenticated role's own policy | **structural** — denied by Vault (status code varies) |
| `ORG_LABEL` | GitHub refusing to mint | **contingent — see below** |

`ORG_LABEL` affects neither authentication nor the key read. It only selects which tenant
namespaces get minted for, so a wrong value is caught only if GitHub refuses the mint — and
that refusal is not guaranteed. The mint sends a **bare repository name** (it comes from the
`nwarila.io/deploy-repo` label, and a Kubernetes label value cannot contain a slash), which
GitHub resolves inside the **minter's own installation**. If a repository of that same name
exists there, the mint SUCCEEDS, and the resulting token is written into the *other* org's
tenant leaf — permitted by the `secret/data/+/provisioned/source-auth` wildcard. The job logs
`OK <namespace> -> <repo>`, so this is silent, not loud. Separately, a wrong `ORG_LABEL` that
matches no tenants exits 0 as a successful no-op.

That is a real residual with two distinct triggers — an accidental misconfiguration as well as
a compromised holder — and is tracked as **TD-0012**.

## The identifier duality (read this first)

Every organization carries **two non-interchangeable identifiers**:

| | Example (hwg) | Example (nwp) | Used by |
|---|---|---|---|
| **Vault path prefix** | `hwg` | `nwp` | Vault paths, resource name suffixes, namespace prefixes |
| **Full GitHub org name** | `the-hero-wars-guys` | `nwarila-platform` | the `nwarila.io/org` namespace label, GitHub API calls |

Conflating them has broken the minter before. `ORG_LABEL` is always the **full name**;
`VAULT_ROLE` and `VAULT_KEY_PATH` always carry the **prefix**.

---

## Prerequisites

1. A GitHub App in the new org with **`contents: read`** (repo-reader shape). Verify by
   minting a token and calling `GET /app` — never trust a `.pem` filename, it carries no
   identity.
2. Its App ID, Installation ID, and private key written to
   `secret/platform/org-pull/<prefix>/gitops-source-auth` with keys
   `githubAppID`, `githubAppInstallationID`, `githubAppPrivateKey`.
3. The private key backed up to `.s3/secrets/org-pull/` and listed in that directory's
   `RESTORE.md`.
4. *(Only if the org publishes private images)* a `read:packages` credential at
   `secret/platform/org-pull/<prefix>/ghcr-pull` as `.dockerconfigjson`. The tenant
   template wires this VaultStaticSecret unconditionally, so a missing path leaves the
   tenant unable to sync it.

---

## Steps

Replace `<prefix>` (e.g. `nwp`) and `<org>` (e.g. `nwarila-platform`) throughout.

### 1. Vault ACL policy
Create `clusters/talos-cluster/apps/vault/vault-config/managed/policy-source-minter-<prefix>.yaml`,
mirroring the hwg file path-for-path with the prefix swapped. It must read only its own
org's App key.

### 2. Vault Kubernetes-auth role
Create `.../managed/role-source-minter-<prefix>.yaml`, binding
`targetServiceAccounts: [source-rotator-<prefix>]` in namespace `source-rotator` to the
policy from step 1.

### 3. Register both in the managed kustomization
Add both files to `.../managed/kustomization.yaml`. New org pairs are **CREATE-class**
(no live object to adopt) — note that in the header, which otherwise claims every CR is
an adoption.

### 4. Grant the operator permission to write them ⚠️
Add two lines to `.../vault-config/bootstrap/vault-config-operator.policy.hcl`:

```hcl
path "sys/policies/acl/source-minter-<prefix>"     { capabilities = ["create", "read", "update"] }
path "auth/kubernetes/role/source-minter-<prefix>" { capabilities = ["create", "read", "update"] }
```

This policy is **exact-path enumerated with no wildcard**, and it is applied
**out-of-band** (ADR-0028) — Flux does not reconcile it. Editing the file is NOT enough;
you must seed it into live Vault:

```bash
# short-TTL admin token in VAULT_TOKEN; never a standing root token
REVOKE_TOKEN_AFTER=true scripts/vault-config/seed-operator-bootstrap.sh
```

**Seed BEFORE merging.** The new grants cover paths the operator will not touch until the
CRs exist, so seeding early is inert and safe, and it removes the failure window entirely.
The script is idempotent (`sys/policies/acl` and `auth/kubernetes/role` writes are upserts;
it reads both back and asserts the live policy matches the authored HCL byte-for-byte), so
re-running is the recovery path too.

If you merge without seeding, the symptoms are:
- the operator 403s writing `sys/policies/acl/source-minter-<prefix>`, so the two CRs never
  reach `ReconcileSuccessful`;
- `vault-config-managed` goes **NotReady** at its 5-minute health-check timeout, and
  `vault-tls-cm` freezes behind its `dependsOn` (cert-manager renewals continue, so no
  certificate outage);
- the new org's Job fails on every schedule — the script logs into Vault *before* it checks
  for tenants, so it errors rather than logging the expected no-op;
- the ROOT `flux-system` Kustomization is unaffected (it sets no `wait`), so this does NOT
  stall the cluster.

Recovery is simply running the seed script; the operator's backoff converges on its own.

Also update the count in `bootstrap/README.md` ("N policies + M roles") — no guard checks
that prose.

### 5. Rotator identity, RBAC, and schedule
Create four files under `clusters/talos-cluster/apps/source-rotator/`:
`serviceaccount-<prefix>.yaml`, `clusterrole-<prefix>.yaml`,
`clusterrolebinding-<prefix>.yaml`, `cronjob-<prefix>.yaml`, and add them to that
directory's `kustomization.yaml`.

- Give each org its **own** ClusterRole and binding. A `ClusterRoleBinding.roleRef` is
  immutable, so re-pointing an existing binding at a shared role makes Flux's
  server-side apply fail on an immutable field and stall the reconcile.
- The CronJob mounts the **shared** `source-rotator-script` ConfigMap. Do not copy the
  script — one reviewed copy of a credential-minting script is the point.
- Set `ORG_LABEL=<org>`, `VAULT_ROLE=source-minter-<prefix>`,
  `VAULT_KEY_PATH=secret/data/platform/org-pull/<prefix>/gitops-source-auth`. All three
  are **required**; the script fails fast rather than defaulting.
- Choose a `schedule` that does not collide with existing rotators (hwg is `*/45`,
  which fires at :00 and :45; nwp is `10,55`). Keep every gap under the 1-hour GitHub
  App token lifetime. Note that staggering only REDUCES concurrency — with
  `activeDeadlineSeconds: 600` a slow job can still overlap the next org's start.
- The pod must carry both `app.kubernetes.io/name: source-rotator` **and**
  `app.kubernetes.io/component: source-token-minter` — the CiliumNetworkPolicy selects on
  that pair, and a pod missing either gets no egress to Vault or GitHub.

### 6. `.gitignore` allowlist ⚠️
The repository denies everything by default (`**`) and allowlists per file. Add all four
new paths from step 5. **Without this the files render and validate locally but are never
committed**, so Flux never sees them and the Kustomization fails on missing resources.
Verify with `git ls-files --error-unmatch <path>`, not `git status`.

### 7. CI guard pinned consumers
Add a tuple for `cronjob-<prefix>.yaml` to `PINNED_CONSUMERS` in
`scripts/check-vault-config-reference-safety.py`. This proves the CronJob's Vault role
reference resolves to an in-git provider, and CI fails if you skip it.

### 8. Documentation
- `docs/explanation/architecture.md`: the rotation subgraph is org-parameterized; add the
  new prefix to the instantiation note.
- `.s3/secrets/org-pull/RESTORE.md`: add the new KV path.

### 9. Kyverno protection — **no action required**
`protect-source-minter.yaml` matches `source-rotator-*` by wildcard, so the new org's
objects are protected on creation. Do not convert it back to an enumerated name list.

---

## Verification

```bash
# every guard, with the new files TRACKED (guards read git ls-files)
git add -A
python3 scripts/check-vault-config-reference-safety.py
python3 scripts/check-vault-policy-no-escalation.py
python3 scripts/check-vault-config-operator-bootstrap-invariants.py
python3 scripts/render-scripts-readme-counts.py --check

# renders + live admission, without mutating anything
kubectl kustomize clusters/talos-cluster/apps/source-rotator
kubectl kustomize clusters/talos-cluster/apps/vault/vault-config/managed
kubectl apply --dry-run=server -f <(kubectl kustomize clusters/talos-cluster/apps/source-rotator)
```

After merge:

```bash
kubectl get kustomization -A | grep -E 'source-rotator|vault-config-managed'   # both Ready
kubectl get policy,kubernetesauthenginerole -n vault-config-operator | grep <prefix>
kubectl create job --from=cronjob/source-rotator-<prefix> -n source-rotator smoke-<prefix>
kubectl logs -n source-rotator job/smoke-<prefix>
```

Until the org's first tenant exists, a **successful no-op** logging
`no tenants for org <org>` is the correct result.

---

## Failure modes this runbook exists to prevent

| Miss | Symptom | Caught by |
|---|---|---|
| Step 4 (bootstrap grant) | CRs stay unreconciled; operator 403s | `vault-config-managed` goes NotReady via healthCheckExprs, and the new org's Jobs go red — but there is **no automated alert**, so nothing surfaces it until someone looks |
| Step 6 (`.gitignore`) | Renders locally, Kustomization fails after merge | nothing — `git status` looks clean |
| Step 7 (pinned consumer) | Reference-safety guard loses scope silently | the guard, only if the pin is *moved* rather than dropped |
| Enumerated Kyverno names | New rotator unprotected from tampering | nothing — policy just doesn't match |
| Shared ClusterRole | Flux apply fails on immutable `roleRef` | Flux reconcile error |
| Wrong `VAULT_ROLE` / `VAULT_KEY_PATH` | The rotator cannot authenticate, or cannot read the App key | **Vault, structurally.** The k8s-auth role binds an exact ServiceAccount name the pod cannot forge, and the authenticated role's policy reads only its own org's App key. Vault denies the cross-org value; the exact status varies (an unknown role and an unauthorized path do not return the same code), so treat "denied" as the guarantee, not a particular code. |
| Wrong `ORG_LABEL` | The rotator mints for another org's tenants | **Nothing structural.** Usually GitHub refuses the mint, but only contingently — the mint sends a bare repo name resolved inside the minter's own installation, so a cross-org name collision makes it SUCCEED and write cross-org while logging `OK`. A label matching no tenants exits 0 as a no-op. Tracked as TD-0012. |
