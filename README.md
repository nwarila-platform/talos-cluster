# TDNHQ-TALCL01

The Talos cluster behind GitLab. A fresh set of six machines becomes a working cluster, with Vault,
a private CA, a GitLab runner and Keycloak (single sign-on for GitLab, federated to Active
Directory), by running the targets below in order. The imperative bootstrap (Talos machine
configs, etcd, the seven platform charts and the Keycloak manifests, Vault init, the realm import)
is `make` + bash; everything after it is Terraform: the GitLab and Keycloak edges (Cloudflare
tunnels and DNS) in `terraform/cloudflare/`, and the GitLab runner, Vault auth and PKI, AWS
identity federation and every onboarded project in `terraform/gitlab-vault/`. A reviewed
`terraform plan` followed by applying exactly that plan is the reconcile.

## Rebuild order

| Target | What it does | Needs |
|---|---|---|
| `init` | checks the local tools and the pinned `talosctl` | — |
| `generate` | generates the six machine configs and the Talos credentials into `.state/` | — |
| `validate` | lints scripts, manifests and Terraform; validates generated configs | — |
| `apply-insecure` | first apply to freshly installed nodes (`apply` afterwards) | `CONFIRM_REBUILD` |
| `bootstrap` | bootstraps etcd once and writes the kubeconfig | `CONFIRM_REBUILD` |
| `platform` | installs Calico, Longhorn, Argo CD and Vault from the pinned charts, cert-manager (with the Vault cluster issuer) and CloudNativePG from their OCI charts **by digest**, the Keycloak operator from the vendored upstream manifests, and applies `platform/keycloak/` (Keycloak waits for its certificate until `gitlab-vault` has run, the connector for its token until `cloudflare` has) | `CONFIRM_REBUILD` |
| `vault-init` | initializes and unseals Vault; writes `.state/vault/init.json`; stores shares 0–2 in the `vault-unseal` Secret for the in-cluster unsealer | `CONFIRM_REBUILD` |
| `cloudflare-plan` | writes a reviewed plan for the GitLab and Keycloak edges after proving every planned object targets the probed account, zone and the two reviewed names, each tunnel configuration and record is bound to the planned tunnel that serves its hostname, and the tunnels, the records and the connector Secret are absent | `CLOUDFLARE_API_TOKEN`, `AWS_PROFILE` |
| `cloudflare` | applies exactly that plan, proves convergence, writes the GitLab connector's token file to `.state/cloudflare/` and proves the in-cluster Keycloak connector rolled out from its Secret; then install the connector on the GitLab host (below) | the same plus `CONFIRM_REBUILD` |
| `cloudflare-verify` | proves both public paths: tunnels healthy, GitLab's OpenID discovery document and JWKS and Keycloak's realm discovery document served through Cloudflare with the expected issuers (run after `keycloak`) | `CLOUDFLARE_API_TOKEN`, `AWS_PROFILE` |
| `gitlab-vault-plan` | discards any earlier accepted plan, writes a candidate plan and prints it for review, proves that every object it would create is absent remotely (directly, or because the same plan creates its container; every lookup fails closed), and only then publishes it as `.state/terraform/gitlab-vault.tfplan` (0600) | `GITLAB_TOKEN`, `VAULT_TOKEN`, `AWS_PROFILE=mgmt-admin` |
| `gitlab-vault` | applies exactly that saved plan (after re-proving absence and that instance runner tokens do not expire), then proves convergence (an empty second plan), the runner-token setting again, and that the runner is online (bounded wait) | the same three, plus `CONFIRM_REBUILD` |
| `keycloak` | creates the realm Secret from `.state/keycloak/` (fail-closed), waits for Keycloak to be ready, imports the `tcn` realm once (Active Directory federation, the `gitlab` client, a realm administrator) and prints the owner steps | `CONFIRM_REBUILD`; `.state/keycloak/svc-keycloak.password` |
| `vault-seed-aws` | seeds one project's static AWS credential | `VAULT_TOKEN`, `GITLAB_PROJECT_ID`, `AWS_*` |
| `health` | checks Talos, nodes, pods, the six expected Helm releases and every Keycloak operand (operators available, issuer and certificate Ready, database healthy with both instances, Keycloak Ready, realm imported without errors, connector rolled out); green only after the whole order has run | — |

Utilities: `kubeconfig` refreshes `.state/configs/kubeconfig`; `selftest` runs the script self-tests
(`vault-init` and `keycloak` against a stubbed `kubectl`, the unsealer against throwaway local Vault
servers; CI runs it too); `vault-configure` is the pre-Terraform way to create one project's Vault role by hand and is
superseded by `gitlab-vault`.

## Inputs

| Variable | Used by | Value |
|---|---|---|
| `CONFIRM_REBUILD` | `apply*`, `bootstrap`, `platform`, `vault-init`, `cloudflare`, `gitlab-vault`, `keycloak` (not `vault-seed-aws`, which writes one KV secret) | the literal `TDNHQ-TALCL01` |
| `CLOUDFLARE_API_TOKEN` | `cloudflare*` | an API token with Cloudflare Tunnel: Edit on the account, DNS: Edit and Zone: Read on the zone |
| `GITLAB_TOKEN` | `gitlab-vault-plan`, `gitlab-vault` | the `platform-terraform` administrator bot's personal access token (`api`, `create_runner`; 7-day; rotate with `POST /api/v4/personal_access_tokens/self/rotate`) — environment only: this root never writes it to a file (curl receives it through a pipe) and the providers' file fallbacks are pre-empted by the constructed environment |
| `VAULT_TOKEN` | `gitlab-vault*`, `vault-seed-aws` | an administrative Vault token (the bootstrap root token from `.state/vault/init.json` today) |
| `AWS_PROFILE` | `cloudflare*`, `gitlab-vault*` | must be `mgmt-admin`; the S3 backend and the AWS provider additionally refuse any account other than 793496711039. `scripts/gitlab-vault.sh` runs every terraform command under a constructed environment, so ambient `AWS_*` keys, `TF_VAR_*`, `TF_CLI_ARGS*`, Vault overrides and `TF_LOG*` cannot change what is planned or applied |
| `GITLAB_PROJECT_ID` | `vault-seed-aws` | from `terraform -chdir=terraform/gitlab-vault output project_ids` |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | `vault-seed-aws` | the dedicated PoC credential |
| `NODES` | `apply`, `apply-insecure` | optional subset of node names |

One input is a file: `.state/keycloak/svc-keycloak.password`, the password of the Active Directory
bind account `svc-keycloak` (`CN=svc-keycloak,OU=Domain Service Accounts,DC=tcn,DC=trinitytechnicalservices,DC=com`),
which the directory's own tooling creates and writes there (0600, one line); `keycloak` refuses to
run without it. The two other realm secrets are generated by `keycloak` itself.

Addresses and pins live in `cluster/config.env` (Talos, Kubernetes, charts — the three Keycloak-era
charts by OCI digest, the operator by vendored checksum — Terraform) and in
`terraform/gitlab-vault/variables.tf` (GitLab URL, Vault addresses, the project list), with
validation on every URL.

The trust boundary is the operator's workstation and shell. What passes through to every
command is `HOME` and `PATH`: the AWS SSO cache, Terraform's CLI configuration under the home
directory (`~/.terraformrc`, `~/.terraform.d/`, including any `dev_overrides` or
`filesystem_mirror` paths it names, wherever they point), `TF_PLUGIN_CACHE_DIR` when set, and the
binaries found on `PATH` are trusted as the operator's own, as are `make` command-line overrides
(`SHELL=`, `.SHELLFLAGS=`, `MAKEFLAGS`). Each root's `.terraform/` data directory and its
`.terraform.lock.hcl` (tracked, read-only during a run) are the only inputs outside the reviewed
source files. Run only through `make`: every recipe runs in bash's privileged mode (`-p`), which
does not source `BASH_ENV`/`ENV`, ignores an inherited `SHELLOPTS`/`BASHOPTS` (a leaked xtrace),
`CDPATH` and `GLOBIGNORE`, and does not import exported shell functions, and the drivers are
started by absolute path in the same mode — so no inherited shell state can print or redirect a
credential before a driver's own `set +x`. Before a driver touches any state, looks up any command
or reads any credential, it proves that its Terraform root is the committed, reviewed tree:
`git status` (ignored files included — the repository's `.gitignore` denies by default, so a
stray `override.tf` or `*.tfvars` would otherwise be invisible) must show nothing but the
`.terraform/` data directory, the tracked set must equal the reviewed file list, and every reviewed
file must be a regular file. Only then do the plan-level checks below run; they are a second
layer, not the proof that the configuration is the reviewed one.

## What Terraform owns and what it refuses to destroy

`gitlab-vault` manages: the instance runner and its Helm release (namespace `gitlab-runner`, the
`gitlab-ca` Secret), the two instance CI variables, the Vault `kv` mount and `gitlab` JWT auth, the
temporary two-tier PKI, the `kubernetes` auth method with the cert-manager issuer's role and
sign-only policy, and for each entry in `var.projects` the group, project, protected `main`,
Vault policy and JWT role, and (once) the `.gitlab-ci.yml`. `cloudflare` manages the two tunnels
(GitLab, Keycloak), their ingress rules and proxied records, and the in-cluster Keycloak connector's
token Secret.

Every durable object carries `prevent_destroy`: the KV mount, the JWT and Kubernetes auth methods,
both PKI mounts, the root certificate, the issuing issuer, the runner, every group, project and
committed CI file, both tunnels and both DNS records. A plan that would destroy one fails. Replacing a CA, rotating the runner, retiring the KV store or
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
| `keycloak/admin.password`, `keycloak/gitlab-client.secret` | `keycloak` (generated once) | yes — the `tcn` realm administrator's initial password and the `gitlab` client secret |
| `keycloak/svc-keycloak.password` | the directory tooling (input) | yes — the Active Directory bind password |
| (paths handed to Terraform) | the drivers | `kubeconfig`, `gitlab/ca.crt`, `vault/tls/ca.crt` are passed to Terraform as absolute `TF_VAR_*` values, so the files the preflight validated are the files the providers use, also under `STATE_DIR_OVERRIDE` |
| `terraform/cloudflare.tfplan` | `cloudflare-plan` | yes — deleted after a successful apply |
| `terraform/gitlab-vault.tfplan` | `gitlab-vault-plan` | yes — a plan embeds sensitive values; deleted after a successful apply, kept after a failed one for diagnosis (delete it yourself before re-planning) |

Terraform state lives in `s3://793496711039-terraform/nwarila-platform/talos-cluster/gitlab-vault.tfstate`
and `…/cloudflare.tfstate` (versioned, SSE-S3, S3 lock file). Treat the bucket as a secret store: the state holds the runner
token (twice: the runner resource and the Helm `set_sensitive` value), every group's and project's
runner registration token, the GitLab and Vault CA certificates, and every CA certificate, CSR and
chain. The CA private keys never enter state (`type = "internal"`). S3 versioning retains old values
after a rotation; never publish a saved plan or raw state, and never run with `TF_LOG` set.

## How Vault stays unsealed

`platform/vault/unsealer.yaml` (applied by `platform` with the rest of `platform/vault`) runs
`platform/vault/unsealer.sh` every minute from the `hashicorp/vault` image: one initial
`vault status` classifies each pod (`vault-0/1/2`, 3-second client timeout); for a sealed pod the
three threshold shares from the `vault-unseal` Secret are submitted on stdin — never in argv —
with the status rechecked after each share and once at the end. A pod restart, a node reboot or a
Talos upgrade therefore heals on the next eligible run, normally within a minute while the
scheduler and the API server are available; a late or deadline-bound Job can make the CronJob skip
one schedule, and a cold start of all three pods can take two runs. The Job exits non-zero, so `health` turns red, when a pod stays sealed, is
unreachable or returns an unreadable status, and when the Secret is missing while Vault is
initialized; it exits zero only when every reachable pod is unsealed or explicitly uninitialized.
The Job runs on the management pool next to Vault, with no service-account token, a read-only
root filesystem, no capabilities and the Restricted Pod Security profile.

The Secret is what makes this possible, so it is also what to protect. It lives in etcd, which
Talos encrypts at rest (`secretboxEncryptionSecret`) on a TPM-sealed LUKS2 volume. A live RBAC
inventory on 2026-10-16 found no namespace-level Secret grant in
`vault` (the Vault service account's own Role covers pods only) but several cluster-wide identities
that can read Secrets everywhere: cluster administrators, the Argo CD controller and server, the
Longhorn service account, the Calico operator and the kube controllers — observed state, not
something these manifests enforce. Whoever can read Secrets in `vault`,
create or exec into a pod there, or control a node or the control plane can still recover the
shares; the Secrets lockdown piece reduces that exposure but cannot make the unsealer the only
possible reader. An etcd backup that contains the Secret must never travel next to a Vault raft
snapshot. `vault-init` may be rerun on a running, initialized cluster with its matching
`init.json`: it requires each share to be one line of base64 that decodes to the 33 bytes a share
of this five-share Shamir initialization has (44 characters, no padding, so a decodable value is
canonical), reads the existing Secret fail-closed (a failed read stops the run; it never decides "absent"
from an error), leaves a matching Secret untouched, refuses one holding different shares, and
creates a missing one with `kubectl create` (which refuses to overwrite). That is how the Secret
is created on a cluster initialized before the unsealer existed — prove it by deleting one
follower pod (it restarts sealed; a standby cannot be sealed in place, Vault answers "cannot seal
when in standby mode") and watching the next Job open it. Create the Secret before the CronJob
exists: a Job that finds Vault initialized and no shares exits 1 by design.
## Runner token

GitLab 19.4 reports no per-runner expiry through the API; `runner_token_expiration_interval`
governs instance runners at registration, and a runner registered while the setting was set keeps
that expiry whatever the setting says later. The driver proves the setting is `null` before
planning, before applying and after applying, which protects every future registration. For the
live runner (`talos-cluster`, id 1, registered by the first `gitlab-vault` apply at 2026-10-16
04:15Z) the recorded facts are only that the setting was `null` at 04:20Z and at 12:06Z — not at
the registration itself — so its token's expiry is **unproven until read from the instance**:
`sudo gitlab-rails runner 'p Ci::Runner.find(1).token_expires_at'` on the GitLab host must print
`nil`; anything else means replace the runner (Replacing the runner) while the setting is observed
`null`. That read is a live-only gate of the edge rollout.

## GitLab edge

GitLab is reachable on the LAN at its own address (the site resolver answers the name with it) and
on the Internet through a dedicated Cloudflare tunnel, `tcnhq-ubt01-gitlab`, whose connector runs
in the cluster (`platform/cloudflared/`, Deployment `cloudflared-gitlab`). `terraform/cloudflare/`
owns the tunnel, its single ingress rule (the GitLab hostname to GitLab's LAN address
`https://10.69.12.11:443`, origin certificate verified against GitLab's own certificate, nothing
else routed), the proxied CNAME, and the `cloudflared/cloudflared-gitlab` Secret holding the
connector's token and that certificate.
The public path exists so AWS IAM can read `/.well-known/openid-configuration` and
`/oauth/discovery/keys`; it also exposes the GitLab sign-in page to the Internet behind nothing but
GitLab's own authentication (Known shortcuts). `make platform` creates the connector (it waits for
its Secret); `make cloudflare` writes the Secret and waits for the connector to come up.

`make cloudflare-verify` then proves the tunnel is healthy and that the discovery document names
`https://gitlab.trinitytechnicalservices.com` as issuer on the public path, resolved over
DNS-over-HTTPS so the site resolver's LAN answer cannot mask a broken edge.

## Keycloak

Keycloak 26.8 runs on the cluster under its operator, with a two-instance PostgreSQL cluster from
CloudNativePG on Longhorn volumes (one instance per node, enforced), a serving certificate issued
and renewed by cert-manager through Vault (Certificates), and one fixed public identity,
`https://keycloak.trinitytechnicalservices.com`, reached two ways. On the LAN the site resolver
answers that name with the cluster's virtual IP, where a Service with `externalIPs` forwards 443
to Keycloak's HTTPS port (`platform/keycloak/service-external.yaml`; the nodes' firewall opens 443
to the two LAN subnets), so GitLab and browsers on site need no Internet. From the Internet a
second dedicated tunnel, `tcnhq-talcl01-keycloak`, whose connector runs as a Deployment in the
`keycloak` namespace, reaches the operator's Service over HTTPS and verifies Keycloak's
certificate against the Vault CA by the public name. Keycloak trusts `X-Forwarded-*` headers from
the pod network only, and the operator creates no Ingress. Ownership, object by object: the
kustomization `platform/keycloak/` holds the namespace, the database cluster, the certificate, the
Keycloak resource, the LAN Service and the connector Deployment (applied by `platform`); the
realm import is a one-shot resource applied by `make keycloak`; the connector's token Secret
belongs to Terraform (`terraform/cloudflare/`); the Vault CA ConfigMap and the issuer's Vault CA
Secret are written imperatively by `platform` from `.state/vault/tls/ca.crt`; the ClusterIssuer and
cert-manager live in `cert-manager`; both operators are installed into `keycloak` **namespace-scoped**
— CloudNativePG from its chart with `config.clusterWide: false`, the Keycloak operator from the
upstream kustomize manifests vendored byte-exact under `platform/keycloak-operator/upstream/`
(the Helm chart is cluster-wide only, and its controllers would hold create/delete rights over every
Secret in the cluster, including `vault/vault-unseal`). Namespace-scoped still leaves cluster-scoped
objects. Every RBAC object and admission webhook the three installs create is pinned in
`scripts/tests/rbac-accepted.json`, a fingerprint generated from the renders of the pinned charts and
reviewed as data; `make validate` (`scripts/tests/check-rbac.py`) fails on any added, removed or
changed object, and re-checks the reasons it was accepted: CloudNativePG keeps ONE ClusterRoleBinding,
for reading nodes (instance placement), get/patch on the webhook configurations (injecting its own CA)
and reading cluster image catalogs — no Secret rule; the Keycloak operator ships four ClusterRole
definitions bound only by RoleBindings inside `keycloak` to its own service account, and no
ClusterRoleBinding at all (the upstream OpenShift ingress binding is deleted); cert-manager's bindings
name only its own service accounts; no rule anywhere uses `*`. CloudNativePG's two admission webhook
configurations have no namespace selector: every create or update of a CloudNativePG resource
(clusters, backups, scheduled backups, databases, poolers) in ANY namespace passes through the operator
in `keycloak`, with `failurePolicy: Fail` — so while that operator is down, no CloudNativePG resource
can be created or changed anywhere. This cluster has CloudNativePG resources only in `keycloak`; the
fingerprint fails validation if the selectors, rules or failure policy change. A chart bump that
changes any of this regenerates the fingerprint (`check-rbac.py … --write`) and that diff is reviewed. The
fingerprint covers authorization (RBAC) and admission webhooks only. The other cluster-scoped objects are
the API types and two named objects: 21 CustomResourceDefinitions (cert-manager 6, CloudNativePG 11,
Keycloak operator 4: `keycloaks`, `keycloakrealmimports`, `keycloakoidcclients`, `keycloaksamlclients`),
the `keycloak` Namespace and the `vault-tcn-server` ClusterIssuer. Those are reviewed through their pinned
sources instead: the charts by digest, the vendored operator bytes by `SHA256SUMS`, the Namespace and
ClusterIssuer manifests in this repository.
A rollback (`kubectl delete -k
platform/keycloak`, `helm uninstall cnpg -n keycloak`, `kubectl delete -k platform/keycloak-operator`)
leaves the Terraform-owned Secret, the Longhorn volumes and the realm's database contents until
those are removed deliberately. The pieces come up as their inputs arrive: the certificate after
`gitlab-vault` created the issuer's Vault role, the connector after `cloudflare` wrote its token
Secret.

`make keycloak` then imports the `tcn` realm once (`platform/keycloak/realm-import.yaml`): a
realm-local administrator `tcn-admin` (password in `.state/keycloak/admin.password`, must be
changed at first login), user federation to Active Directory over plain LDAP to both domain
controllers (read-only, users imported on first login, `sAMAccountName` as the username,
disabled accounts filtered out) with the bind account `svc-keycloak` and the seven attribute
mappers Keycloak would otherwise create itself (username, full name from `cn`, last name, email,
creation and modification dates, the AD account-control mapper — an import through `components`
does not run that hook, so the realm declares the seven non-Kerberos mappers it would create for
these provider settings, and `validate` compares them byte-exact and requires Kerberos to stay off —
both flags off and no `krbPrincipalAttribute`, with which onCreate would add a Kerberos principal
mapper), and the confidential
OpenID Connect client `gitlab` whose only redirect is GitLab's callback. Secret values enter the
realm through the operator's placeholder mechanism from the `keycloak-realm-secrets` Secret,
which the script creates from `.state/keycloak/` with `kubectl create` and refuses to overwrite
when it holds different values. An imported realm is never overwritten by a later import; later
changes are made in the admin console (`https://keycloak.trinitytechnicalservices.com/admin/`;
the master-realm bootstrap administrator is `temp-admin`, password in the
`keycloak-initial-admin` Secret) or by a reviewed re-creation.

Two owner steps remain outside the repository, and the script prints them: the site resolver's
host override `keycloak.trinitytechnicalservices.com → 10.69.112.62` (OPNsense Unbound, a UI
step until the resolver is under Terraform), and GitLab's OmniAuth block from
`platform/gitlab-host/gitlab.rb.keycloak` with the client secret and the Vault CA in
`/etc/gitlab/trusted-certs/` (GitLab talks to Keycloak over HTTPS on the LAN path). Users who
sign in through Keycloak are created in GitLab blocked until an administrator approves them; an
existing GitLab user with the same username is linked automatically.

## How a job reaches AWS

`gitlab-vault` registers GitLab as an OpenID Connect identity provider in account 793496711039
(audience `sts.amazonaws.com`; IAM fetches and keeps the issuer's CA thumbprint itself) and, for
each project with `aws_access = true`, sets the project's ID-token subject to carry `ref_protected`
and creates the IAM role `gitlab_<group>_<project>` whose trust policy accepts only ID tokens with
`sub = project_path:<group>/<project>:ref_type:branch:ref:main:ref_protected:true` — the same
protected `main` the Vault role relies on — and attaches the proof permission: write and
read SSM parameters under `/gitlab/poc/<group>/<project>/` and nothing else. Two instance-level CI
variables, `AWS_ACCOUNT_ID` and `AWS_REGION`, let a job build its role ARN from `CI_PROJECT_PATH`.
The job hands the token to the AWS CLI through `AWS_WEB_IDENTITY_TOKEN_FILE`, so it never appears
in an argument; [examples/aws-oidc-poc/.gitlab-ci.yml](examples/aws-oidc-poc/.gitlab-ci.yml) is
the complete example. The preflight refuses to plan the identity provider until the public path
serves the discovery document, because IAM reads it at creation.

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
| IAM identity provider for the GitLab issuer | the public discovery document and JWKS must be served (DNS-over-HTTPS resolution), then `aws iam get-open-id-connect-provider` must answer NoSuchEntity | `terraform import aws_iam_openid_connect_provider.gitlab arn:aws:iam::793496711039:oidc-provider/<host>` |
| IAM role `gitlab_<group>_<project>` and its inline policy | `aws iam get-role` NoSuchEntity; the policy by containment in a planned role, else `aws iam get-role-policy` | `terraform import 'aws_iam_role.project["<key>"]' <name>` |
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
| Vault auth `kubernetes`, its configuration, policy `cert-manager-tcn-server`, role `vault-issuer` | `sys/auth`; the configuration only by containment in a planned auth backend (writing it onto an existing backend is refused); the policy under `sys/policies/acl/`; the role by containment, else `auth/kubernetes/role/vault-issuer` | `terraform import vault_auth_backend.kubernetes kubernetes`, `terraform import vault_kubernetes_auth_backend_config.kubernetes auth/kubernetes/config`, `terraform import vault_policy.cert_manager_tcn_server cert-manager-tcn-server`, `terraform import vault_kubernetes_auth_backend_role.vault_issuer auth/kubernetes/role/vault-issuer` |
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

`cloudflare-plan` applies the same discipline to the edge: a planned tunnel must carry one of the
two reviewed names and be remotely configured; a tunnel configuration's `tunnel_id` must be
unknown in the plan and reference exactly one tunnel the same plan creates, and its ingress must
be exactly that tunnel's hostname followed by the catch-all; a record must carry one of the two
reviewed hostnames, be proxied, and derive its content from the tunnel that serves that hostname;
the only Secret the root may create is `keycloak/cloudflared-keycloak`, proven absent with
`kubectl get` (NotFound only). Tunnels and records are proven absent by name through the
Cloudflare API before the plan is published.

## Certificates

`gitlab-vault` builds a two-tier CA inside Vault: `pki-root` (EC P-384, ten years, temporary) signs
`pki-int-linux` (EC P-384, five years), and the `tcn-server` role issues 90-day server certificates
for names under `trinitytechnicalservices.com` (subdomains and IP SANs allowed; wildcards, bare
domain, localhost and client EKU refused). The role does not authorize IP SANs beyond syntax, so
access to its issue endpoint must stay operator-only. Everything downstream binds to
`pki-int-linux`, so replacing the root later only re-signs the issuing CA. No AIA or CRL
distribution points are set until a stable publication host exists.

Inside the cluster, cert-manager issues through that CA without any stored credential: the
`vault-tcn-server` ClusterIssuer (`platform/cert-manager/issuer.yaml`) logs in to Vault's
`kubernetes` auth method with a ten-minute token minted for the `vault-issuer` service account
(Vault verifies it through the TokenReview API with its own service account), and the role
`vault-issuer` (`terraform/gitlab-vault/vault-k8s-auth.tf`) grants a policy whose only capability
is `pki-int-linux/sign/tcn-server`. Vault's own serving certificate is trusted through the
`vault-ca` Secret in `cert-manager` (written by `platform` from `.state/vault/tls/ca.crt`).
Keycloak's certificate (`platform/keycloak/certificate.yaml`) is a 90-day P-384 certificate for
its public name, renewed 30 days before expiry with a fresh key; the Cloudflare connector and
GitLab verify it against the same Vault CA. The issuer reports not ready until `gitlab-vault` has
created its Vault role; the Keycloak pod waits for the certificate Secret until then.

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
- The GitLab server certificate is self-signed and trusted by file (trust on first use) on the LAN
  and by the tunnel connector; Cloudflare issues the public certificate.
- The public GitLab hostname reaches the sign-in page with GitLab's own authentication only; a
  Cloudflare Access policy in front of everything but the OpenID discovery paths is the next edge
  change, and GitLab's `real_ip` trust for Cloudflare's ranges is not yet set on the host.
- The `vault-unseal` Secret is readable by every identity with Secret access in `vault` (and by
  anyone who can run or exec a pod there); the Secrets lockdown piece reduces, not removes, that.
  cert-manager adds cluster-wide Secret readers and writers of its own (its controller, cainjector
  and the ClusterIssuer/Certificate controllers manage certificate Secrets in every namespace),
  accepted because the ClusterIssuer design needs them; the Keycloak operator and CloudNativePG are
  installed namespace-scoped precisely so that they do not (CloudNativePG's one cluster-wide binding
  carries no Secret rule; see Keycloak above).
- Keycloak's database has no PostgreSQL-native backup: only Longhorn's daily volume backup of its
  two volumes (the default recurring-job group), with no WAL archiving, no point-in-time recovery
  and no restore test yet (KC1-BK).
- Keycloak binds to Active Directory over plain LDAP (`ldap://`, port 389): the domain controllers
  present no certificate yet. Accepted by the owner until the directory's certificate authority
  exists; the bind password travels in clear on the node network, so the account is read-only and
  the switch to LDAPS (and X.509 login) follows that CA.
- Keycloak's LAN entry point uses `Service.spec.externalIPs`, a deprecated API this cluster's
  kube-proxy still implements; a load balancer replaces it. The resolver's host override and the
  GitLab `gitlab.rb` block are owner steps until the resolver and the GitLab host are under
  configuration management.
- The `keycloak` namespace enforces the Baseline profile (Restricted is audited and warned): the
  Keycloak operator sets no security context on the server pod, so the Keycloak resource adds one
  through its pod template; enforce moves to Restricted after a live run shows no warning.
- One Keycloak instance, one realm import: scaling out needs cache clustering across pods, and
  realm changes after the import are made in the admin console, not reconciled from the file. The
  master-realm `temp-admin` bootstrap account should be replaced by a named administrator.
- `.state/` is workstation-local; a pipeline-driven rebuild needs it in durable storage (S3).
- `scripts/configure-vault-gitlab.sh` duplicates what `gitlab-vault` does and should be deleted.
- Certificate issuance is a documented recipe, not yet a tested script.
