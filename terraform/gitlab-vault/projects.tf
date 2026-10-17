# Per-project onboarding: a GitLab project with a protected main branch, in a
# group or one level of subgroup. Adding a project = adding one entry to
# var.projects. Vault access needs no entry: every project's protected main
# reads its own secrets through the one ci role below.
locals {
  # The namespace a project lives in: its key without the last segment.
  project_parent = { for key in keys(var.projects) : key => join("/", slice(split("/", key), 0, length(split("/", key)) - 1)) }
  top_groups     = toset([for key in keys(var.projects) : split("/", key)[0]])
  sub_groups     = toset([for parent in values(local.project_parent) : parent if length(split("/", parent)) == 2])
}

# Instance setting: allow "Repository by URL" imports, which a project with an
# import_url needs (GitLab ships with every import source off). Terraform
# manages only the attribute set here; the rest of the settings stay as they are.
resource "gitlab_application_settings" "this" {
  import_sources = ["git"]
}

resource "gitlab_group" "this" {
  for_each = local.top_groups

  name             = each.value
  path             = each.value
  visibility_level = "private"

  # Groups and projects hold data: offboarding is a reviewed procedure
  # (README), never a map-key removal.
  permanently_remove_on_delete = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "gitlab_group" "sub" {
  for_each = local.sub_groups

  name                         = split("/", each.value)[1]
  path                         = split("/", each.value)[1]
  parent_id                    = gitlab_group.this[split("/", each.value)[0]].id
  visibility_level             = "private"
  permanently_remove_on_delete = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "gitlab_project" "this" {
  for_each = var.projects

  name = reverse(split("/", each.key))[0]
  path = reverse(split("/", each.key))[0]
  namespace_id = (length(split("/", local.project_parent[each.key])) == 1
    ? gitlab_group.this[local.project_parent[each.key]].id
  : gitlab_group.sub[local.project_parent[each.key]].id)
  visibility_level       = "private"
  initialize_with_readme = each.value.import_url == null ? true : null
  import_url             = each.value.import_url
  default_branch         = "main"
  # An imported repository keeps its own history: merge requests fast-forward
  # (no merge commits, signatures intact) and need a green pipeline.
  merge_method                          = each.value.import_url == null ? "merge" : "ff"
  only_allow_merge_if_pipeline_succeeds = each.value.import_url != null
  archived                              = each.value.archived
  # Projects that assume an IAM role carry ref_protected in their ID-token
  # subject (GitLab 18.7+; measured on 19.4: the project setting exists and
  # defaults to project_path, ref_type, ref), so the trust policy can pin it.
  ci_id_token_sub_claim_components = each.value.aws_access ? ["project_path", "ref_type", "ref", "ref_protected"] : ["project_path", "ref_type", "ref"]

  # Destroying a project archives it; permanent deletion (the provider's
  # mutually exclusive permanently_delete_on_destroy) stays at its default, off.
  archive_on_destroy = true

  depends_on = [gitlab_application_settings.this]

  lifecycle {
    prevent_destroy = true
  }
}

# The Vault role binds ref_protected=true, so main must stay protected, nobody
# may push to it directly, and only an administrator may unprotect it (GitLab's
# default lets maintainers unprotect, push, and re-protect). Changes reach main
# through merge requests. GitLab protects the default branch at project
# creation (maintainers may push); the optional CI file is committed under that
# initial policy — the one bootstrap exception — then the provider replaces the
# protection with this one. The provider accepts only the allowed_to_* form on an
# EE binary (the *_access_level attributes are CE-only); on this EE Free instance
# the access_level-only entries were measured to be accepted (201), read back as
# push 0 / merge 40 / unprotect 60, and enforced (an administrator's direct
# commit to main is refused with 403).
resource "gitlab_branch_protection" "main" {
  for_each = var.projects

  project          = gitlab_project.this[each.key].id
  branch           = "main"
  allow_force_push = false

  allowed_to_push = [
    { access_level = "no one" },
  ]
  allowed_to_merge = [
    { access_level = "maintainer" },
  ]
  allowed_to_unprotect = [
    { access_level = "admin" },
  ]

  depends_on = [gitlab_repository_file.ci]
}

# Every project's own Vault secrets, with no per-project setup: one JWT role for
# all projects, and one policy whose path Vault fills in from the token itself.
# The role's user claim is the ID token's project_id, so each project logs in as
# its own entity whose alias name is its numeric id, and the templated path
# below resolves to that project's kv/ci/production/project-<id>/ and nothing
# else. GitLab signs the token, so a job cannot name another project's id. Only
# a protected main branch logs in; a project without one gets nothing.
resource "vault_policy" "ci_project" {
  name = "ci-project"
  # Deprecated attribute, kept on purpose: with it the provider refuses to
  # create over a policy that appeared after the plan (measured) instead of
  # silently replacing it.
  allow_overwrite = false
  policy          = <<-EOT
    path "kv/data/ci/production/project-{{identity.entity.aliases.${vault_jwt_auth_backend.gitlab.accessor}.name}}/*" {
      capabilities = ["read"]
    }
    path "kv/metadata/ci/production/project-{{identity.entity.aliases.${vault_jwt_auth_backend.gitlab.accessor}.name}}/*" {
      capabilities = ["read", "list"]
    }
    # The role withholds the default policy, which is what normally lets a
    # token revoke itself (measured: permission denied without this path).
    path "auth/token/revoke-self" {
      capabilities = ["update"]
    }
  EOT
}

resource "vault_jwt_auth_backend_role" "ci" {
  backend           = vault_jwt_auth_backend.gitlab.path
  role_name         = "ci"
  role_type         = "jwt"
  bound_audiences   = [var.vault_incluster_url]
  user_claim        = "project_id"
  bound_claims_type = "string"
  bound_claims = {
    ref           = "main"
    ref_type      = "branch"
    ref_protected = "true"
  }
  token_policies          = [vault_policy.ci_project.name]
  token_no_default_policy = true
  token_ttl               = 600
  token_explicit_max_ttl  = 600
}

# Optional pipeline definition committed ONCE to main (the PoC job for
# poc/vault-gitlab-poc). After that the repository owns the file: edits go
# through merge requests, so later content changes here are ignored, and the
# file is never deleted by Terraform.
resource "gitlab_repository_file" "ci" {
  for_each = { for key, project in var.projects : key => project.ci_file if project.ci_file != null }

  project             = gitlab_project.this[each.key].id
  file_path           = ".gitlab-ci.yml"
  branch              = "main"
  encoding            = "base64"
  content             = base64encode(file(each.value))
  commit_message      = "ci: vault PoC pipeline"
  overwrite_on_create = false

  lifecycle {
    ignore_changes  = [content]
    prevent_destroy = true
  }
}
