# TDNHQ-TALCL01

The Talos cluster behind GitLab. A fresh set of six machines becomes a working cluster, with Vault,
a private CA and a GitLab runner, by running the targets below in order. The imperative bootstrap
(Talos machine configs, etcd, the four platform charts, Vault init) is `make` + bash; everything
after it — the GitLab runner, Vault auth and PKI, and every onboarded project — is one Terraform
root, `terraform/gitlab-vault/`. A reviewed `terraform plan` followed by applying exactly that plan
is the reconcile.

## Rebuild order

| Target | What it does | Needs |
|---|---|---|
| `init` | checks the local tools and the pinned `talosctl` | — |
| `generate` | generates the six machine configs and the Talos credentials into `.state/` | — |
| `validate` | lints scripts, manifests and Terraform; validates generated configs | — |
| `apply-insecure` | first apply to freshly installed nodes (`apply` afterwards) | `CONFIRM_REBUILD` |
| `bootstrap` | bootstraps etcd once and writes the kubeconfig | `CONFIRM_REBUILD` |
| `platform` | installs Calico, Longhorn, Argo CD and Vault from the pinned charts | `CONFIRM_REBUILD` |
| `vault-init` | initializes and unseals Vault; writes `.state/vault/init.json` | `CONFIRM_REBUILD` |
| `gitlab-vault-plan` | discards any earlier accepted plan, writes a candidate plan and prints it for review, proves that every object it would create is absent remotely (directly, or because the same plan creates its container; every lookup fails closed), and only then publishes it as `.state/terraform/gitlab-vault.tfplan` (0600) | `GITLAB_TOKEN`, `VAULT_TOKEN`, `AWS_PROFILE=mgmt-admin` |
| `gitlab-vault` | applies exactly that saved plan, then proves convergence (an empty second plan), that the runner's token does not expire, and that the runner is online (bounded wait) | the same three, plus `CONFIRM_REBUILD` |
| `vault-seed-aws` | seeds one project's static AWS credential | `VAULT_TOKEN`, `GITLAB_PROJECT_ID`, `AWS_*` |
| `health` | checks Talos, nodes, pods and the expected Helm releases | — |

Utilities: `kubeconfig` refreshes `.state/configs/kubeconfig`; `vault-configure` is the pre-Terraform
way to create one project's Vault role by hand and is superseded by `gitlab-vault`.

## Inputs

| Variable | Used by | Value |
|---|---|---|
| `CONFIRM_REBUILD` | `apply*`, `bootstrap`, `platform`, `vault-init`, `gitlab-vault` (not `vault-seed-aws`, which writes one KV secret) | the literal `TDNHQ-TALCL01` |
| `GITLAB_TOKEN` | `gitlab-vault-plan`, `gitlab-vault` | the `platform-terraform` administrator bot's personal access token (`api`, `create_runner`; 7-day; rotate with `POST /api/v4/personal_access_tokens/self/rotate`) — environment only: this root never writes it to a file (curl receives it through a pipe) and the providers' file fallbacks are pre-empted by the constructed environment |
| `VAULT_TOKEN` | `gitlab-vault*`, `vault-seed-aws` | an administrative Vault token (the bootstrap root token from `.state/vault/init.json` today) |
| `AWS_PROFILE` | `gitlab-vault*` | must be `mgmt-admin`; the S3 backend additionally refuses any account other than 793496711039. `scripts/gitlab-vault.sh` runs every terraform command under a constructed environment, so ambient `AWS_*` keys, `TF_VAR_*`, `TF_CLI_ARGS*`, Vault overrides and `TF_LOG*` cannot change what is planned or applied |
| `GITLAB_PROJECT_ID` | `vault-seed-aws` | from `terraform -chdir=terraform/gitlab-vault output project_ids` |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | `vault-seed-aws` | the dedicated PoC credential |
| `NODES` | `apply`, `apply-insecure` | optional subset of node names |

Addresses and pins live in `cluster/config.env` (Talos, Kubernetes, charts, Terraform) and in
`terraform/gitlab-vault/variables.tf` (GitLab URL, Vault addresses, the project list), with
validation on every URL.

`HOME` and `PATH` do pass through to every command: the AWS SSO cache, Terraform's CLI
configuration and provider overrides under the home directory, and the binaries on `PATH` are
trusted as the operator's own. Run only from the trusted workstation.

## What Terraform owns and what it refuses to destroy

`gitlab-vault` manages: the instance runner and its Helm release (namespace `gitlab-runner`, the
`gitlab-ca` Secret), the two instance CI variables, the Vault `kv` mount and `gitlab` JWT auth, the
temporary two-tier PKI, and for each entry in `var.projects` the group, project, protected `main`,
Vault policy and JWT role, and (once) the `.gitlab-ci.yml`.

Every durable object carries `prevent_destroy`: the KV mount, the JWT auth, both PKI mounts, the
root certificate, the issuing issuer, the runner, every group, project and committed CI file. A plan
that would destroy one fails. Replacing a CA, rotating the runner, retiring the KV store or
offboarding a project are each a reviewed change:

- **Offboarding a project** is two switches on its `var.projects` entry, never a removed key:
  first `vault_access = false` (apply: only the Vault role and policy disappear, nothing in GitLab
  changes), later `archived = true` (apply: the project is archived in place). The entry, its
  protected branch and its CI file stay under management; permanent deletion is never configured.
- **Replacing the runner:** remove its guard, apply (the chart re-seeds the new token), confirm the
  new runner is online; the old token cannot be recovered or imported, and an out-of-band token reset
  is not detected by `plan` — treat it as a replacement.
- **Replacing the root CA (the offline ceremony):** re-sign the issuing CA; consumers bind to
  `pki-int-linux` and do not change.

## State

`.state/` is gitignored and must be escrowed outside this repository after every change.

| Path | Written by | Secret |
|---|---|---|
| `secrets/talos-secrets.yaml` | `generate` | yes — the cluster's root of trust |
| `configs/talosconfig`, `configs/kubeconfig` | `generate`, `bootstrap`/`kubeconfig` | yes |
| `generated/{controlplane,worker}/*.yaml` | `generate` | yes (contain the Talos secrets) |
| `vault/tls/*` | `platform` (`vault-tls.sh`) | `ca.key`, `tls.key` yes; `ca.crt` is the public trust anchor jobs use |
| `vault/init.json` | `vault-init` | yes — unseal keys and root token |
| `gitlab/ca.crt` | you, once: the GitLab server certificate (PEM) | no (public certificate) |
| `gitlab/admin-token`, `gitlab/root-password` | the one-time bootstrap on the GitLab host | yes |
| `terraform/gitlab-vault.tfplan` | `gitlab-vault-plan` | yes — a plan embeds sensitive values; deleted after a successful apply, kept after a failed one for diagnosis (delete it yourself before re-planning) |

Terraform state lives in `s3://793496711039-terraform/nwarila-platform/talos-cluster/gitlab-vault.tfstate`
(versioned, SSE-S3, S3 lock file). Treat the bucket as a secret store: the state holds the runner
token (twice: the runner resource and the Helm `set_sensitive` value), every group's and project's
runner registration token, the GitLab and Vault CA certificates, and every CA certificate, CSR and
chain. The CA private keys never enter state (`type = "internal"`). S3 versioning retains old values
after a rotation; never publish a saved plan or raw state, and never run with `TF_LOG` set.

## How a job reaches Vault

`gitlab-vault` sets two instance-level CI variables for every project: `VAULT_ADDR`
(`var.vault_incluster_url`) and `VAULT_CACERT` (a file variable holding `.state/vault/tls/ca.crt`),
and gives each project in `var.projects` a Vault JWT role `ci-<group>-<project>` (the key with `/`
replaced by `-`; a job derives the same name from `CI_PROJECT_PATH`, and the name is known before the
project exists so the preflight can probe it) bound to that project's numeric id, to `main`, and to
protected refs, with read access to `kv/data/ci/production/project-<id>/aws` only.
`main` is protected with **no direct push**, merges by maintainers, force-push off, and **unprotect by
administrators only** (GitLab's default would let a maintainer unprotect, push and re-protect). The
provider sends the `allowed_to_*` form; GitLab documents it as Premium/Ultimate, but on this EE Free
instance the access-level-only entries were measured to be accepted, read back exactly, and
enforced (an administrator's direct commit returns 403), and the Vault role is created only after the
protection. So a job that carries `ref_protected=true` reached `main` through a merge request — with
one bootstrap exception: the optional `.gitlab-ci.yml` is committed by the `platform-terraform` administrator
once, at project creation, under GitLab's initial protection, before this policy replaces it. From
then on the file belongs to the repository (edit it through merge requests; Terraform ignores its
content and never deletes it) — which also means Terraform no longer verifies what the job does. A job requests an ID token with
`aud: <vault_incluster_url>` and logs in at `auth/gitlab/login`;
[examples/vault-gitlab-poc/.gitlab-ci.yml](examples/vault-gitlab-poc/.gitlab-ci.yml) is the complete
example. Onboarding another repository is one more entry in `var.projects`; the preflight below refuses
the plan if any object it would create already exists.

## Preflight: every planned create must be genuine

A plan that shows creates does not prove the objects are absent: Terraform plans a create for any
object missing from *state*. `gitlab-vault-plan` therefore writes the plan to a candidate file
unique to that run (never applyable) and checks every create in it against the live systems; only
a plan that passed is renamed to `.state/terraform/gitlab-vault.tfplan`. Starting a new plan first
discards the previous accepted plan and any candidate a killed run left behind, so no failure the
shell can handle leaves an older plan behind, and on every such exit the candidate is removed. A
kill (SIGKILL, power loss) leaves one of three states, so inspect the plan directory after any
killed run before deciding what to apply: before the old plan was voided, that old plan (it passed
its own checks); between voiding and publication, nothing applyable and at most one non-applyable
candidate (sensitive, 0600; the next run removes it); after publication, the new, checked plan.
Plan and apply hold a lock in the plan directory, so a second run is refused rather than allowed
to replace a plan another run is checking or applying. `gitlab-vault` repeats the whole check
against the saved plan immediately before `terraform apply`, so an object that appeared during
the review interval stops the apply instead of being overwritten; for the per-project policy,
`allow_overwrite = false` makes the provider refuse as a second barrier (Terraform prints that
attribute's deprecation warning on every plan — expected). A killed run can also leave its
scratch directory `run.*` (API responses only, never a token); the next run removes it. A plan that would *replace* an object
(Terraform's delete-and-create) is refused outright: this guard proves absence for pure creates,
and a replacement means the object exists — review and apply such a change deliberately with
Terraform itself. A create passes when
the object's own API gives a positive not-found, or when the object that contains it (its mount,
auth backend or namespace; for a repository file or branch protection, its project) is created by
the same plan and so cannot hold anything yet. Any other answer — an error, a response of the wrong
shape, a resource type the preflight has no rule for — aborts. Objects that already exist are
listed with their import ids; decide each before planning again. `terraform plan` itself changes
nothing this root manages, but it does take the S3 state lock briefly and the Vault provider mints
a short-lived child token for the run.

| Planned create | Proven absent by | If present |
|---|---|---|
| Vault mounts `kv`, `pki-root`, `pki-int-linux` | `sys/mounts` | `terraform import vault_mount.kv kv` (same for `pki_root`, `pki_int`), then the rows below for their contents |
| Vault auth `gitlab` | `sys/auth` | `terraform import vault_jwt_auth_backend.gitlab gitlab` |
| PKI root issuer and key `temp-root`, issuing key and issuer `linux-issuing`, role `tcn-server` | containment in a planned mount, else the mount's issuer and key listings and `roles/` | issuer: `terraform import vault_pki_secret_backend_issuer.int pki-int-linux/issuer/<issuer_id>`; role: `terraform import vault_pki_secret_backend_role.tcn_server pki-int-linux/roles/tcn-server`; a generated root certificate or key cannot be imported — remove it or use another mount path |
| Signing the intermediate, importing it, the default-issuer setting | allowed only when their mount is created by the same plan; otherwise the plan is refused. These are actions, not objects: re-signing issues a new serial, importing a re-signed certificate adds a second issuer, and the setting overwrites the default (measured) | reconcile state with Vault first: list `pki-int-linux/issuers` and `keys`, the serials under `pki-root/certs`, and `config/issuers`; import the surviving issuer and key addresses or remove strays; then plan again |
| Instance variables `VAULT_ADDR`, `VAULT_CACERT` | `/admin/ci/variables/<key>` | `terraform import gitlab_instance_variable.vault_addr VAULT_ADDR` |
| Group, project | `/groups/<path>`, `/projects/<path>` | `terraform import 'gitlab_group.this["<group>"]' <id>`, `terraform import 'gitlab_project.this["<group>/<project>"]' <id>` |
| `.gitlab-ci.yml` on `main` | containment in a planned project, else `/projects/<id>/repository/files/` | `terraform import 'gitlab_repository_file.ci["<key>"]' '<id>:main:.gitlab-ci.yml'`, or set `ci_file = null` and land it through a merge request (`overwrite_on_create = false` means an unimported file conflicts) |
| Protection of `main` | containment in a planned project (GitLab's own default protection on the new project is then taken over, see above), else `/projects/<id>/protected_branches/main` | `terraform import 'gitlab_branch_protection.main["<key>"]' <id>:main` — settle the file row first: with the no-push rule in force the bootstrap commit is impossible |
| Per-project Vault policy and role | `sys/policies/acl/<name>` directly (a policy is global; nothing contains it); the role by containment in a planned auth backend, else `auth/gitlab/role/<name>`. Both names come from the project key and are known at plan time | `terraform import 'vault_policy.project_aws_read["<key>"]' ci-<group>-<project>-aws-read`, `terraform import 'vault_jwt_auth_backend_role.project["<key>"]' auth/gitlab/role/ci-<group>-<project>` |
| Instance runner `talos-cluster` | the paginated instance-runner list | cannot be imported with its token: replace deliberately (jobs wait until the new runner is online) |
| Namespace `gitlab-runner` | `kubectl get namespace` (NotFound only) | `terraform import kubernetes_namespace_v1.gitlab_runner gitlab-runner` |
| Secret `gitlab-ca`, Helm release `gitlab-runner` | containment in a planned namespace, else `kubectl get secret` (NotFound only) and `helm list -o json` | `terraform import kubernetes_secret_v1.gitlab_ca gitlab-runner/gitlab-ca`, `terraform import helm_release.gitlab_runner gitlab-runner/gitlab-runner` |

Vault answers a missing object under an existing mount with 404 and an empty error list; a 404 that
names "no handler for route" means the mount is gone although state records it, and is treated as
undecidable. Every answer is first checked for the complete shape the decision needs (an inventory
of `path/` keys to objects, runner entries with a string description, issuer and key entries with a
string name, Helm entries with string name and namespace) and then reduced to a literal true or
false before it is used, and every identity the plan must carry for a create (path, key, name,
backend, branch, namespace) must be a non-empty string; otherwise the run aborts. So neither a parse
error, nor a well-formed answer of the wrong shape, nor a plan entry without an identity can read
as "absent".

## Certificates

`gitlab-vault` builds a two-tier CA inside Vault: `pki-root` (EC P-384, ten years, temporary) signs
`pki-int-linux` (EC P-384, five years), and the `tcn-server` role issues 90-day server certificates
for names under `trinitytechnicalservices.com` (subdomains and IP SANs allowed; wildcards, bare
domain, localhost and client EKU refused). The role does not authorize IP SANs beyond syntax, so
access to its issue endpoint must stay operator-only. Everything downstream binds to
`pki-int-linux`, so replacing the root later only re-signs the issuing CA. No AIA or CRL
distribution points are set until a stable publication host exists.

Issuing a certificate returns the **private key in the response**, so never run a bare
`vault write pki-int-linux/issue/...` in a logged terminal. Until the tested issuance script lands,
use this fail-closed block: it stops at the first missing field, proves the key matches the
certificate and the chain, builds the whole set in a new, uniquely named version directory on the destination
filesystem (so two runs can never merge into one directory), and only then switches the `current`
symlink in a single rename, so an in-service bundle is never half-replaced:

```
( set -euo pipefail; umask 077
  cn=<fqdn>; sans=<dns,dns>; ips=<ip>; out=<destination directory>
  install -d -m 0700 "$out" "$out/versions"; d="$(mktemp -d "$out/versions/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"; trap 'rm -rf "${d:?}"' EXIT
  vault write -format=json pki-int-linux/issue/tcn-server common_name="$cn" alt_names="$sans" ip_sans="$ips" > "$d/issue.json"
  jq -er '.data.private_key | select(type == "string")' "$d/issue.json" > "$d/tls.key"
  jq -er '.data.certificate | select(type == "string")' "$d/issue.json" > "$d/tls.crt"
  jq -er '.data.ca_chain | select(type == "array") | .[]' "$d/issue.json" > "$d/ca-chain.crt"
  rm -f "$d/issue.json"; chmod 0600 "$d/tls.key"; chmod 0644 "$d/tls.crt" "$d/ca-chain.crt"
  [ "$(openssl x509 -in "$d/tls.crt" -noout -pubkey)" = "$(openssl pkey -in "$d/tls.key" -pubout)" ]
  openssl verify -CAfile <(vault read -field=certificate pki-root/issuer/temp-root) -untrusted "$d/ca-chain.crt" "$d/tls.crt" > /dev/null
  trap - EXIT; rm -f "$out/.current.tmp"
  ln -s "versions/${d##*/}" "$out/.current.tmp" && mv -T "$out/.current.tmp" "$out/current"
  echo "issued $cn; files under $out/current/" )
```

## Known shortcuts (to be removed)

- The root CA private key lives inside Vault; the offline root ceremony replaces it.
- `VAULT_TOKEN` is the bootstrap root token; a scoped admin token should replace it, and
  `terraform apply` should run from a GitLab pipeline using a Vault role of its own.
- The GitLab server certificate is self-signed and trusted by file (trust on first use) until the
  Cloudflare tunnel fronts GitLab.
- `.state/` is workstation-local; a pipeline-driven rebuild needs it in durable storage (S3).
- `scripts/configure-vault-gitlab.sh` duplicates what `gitlab-vault` does and should be deleted.
- Certificate issuance is a documented recipe, not yet a tested script.
- Longhorn is expected by `platform` and `health` but is not yet installed on the live cluster.
