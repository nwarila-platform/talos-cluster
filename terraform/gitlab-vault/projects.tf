# Per-project onboarding: a GitLab project with a protected main branch and a
# Vault role that only that project's protected-main jobs can assume, with read
# access to that project's own KV path. Adding a project = adding one entry to
# var.projects.
locals {
  project_groups = toset([for key in keys(var.projects) : split("/", key)[0]])
}

resource "gitlab_group" "this" {
  for_each = local.project_groups

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

resource "gitlab_project" "this" {
  for_each = var.projects

  name                   = split("/", each.key)[1]
  path                   = split("/", each.key)[1]
  namespace_id           = gitlab_group.this[split("/", each.key)[0]].id
  visibility_level       = "private"
  initialize_with_readme = true
  default_branch         = "main"
  archived               = each.value.archived

  # Destroying a project archives it; permanent deletion (the provider's
  # mutually exclusive permanently_delete_on_destroy) stays at its default, off.
  archive_on_destroy = true

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

# Vault access is a separate switch from project ownership so that revoking it
# is a one-resource change that leaves the repository untouched.
locals {
  vault_projects = { for key, project in var.projects : key => project if project.vault_access }
  # Vault names come from the project key, not its id: a job computes the same
  # name from CI_PROJECT_PATH, and the preflight can probe a name that is known
  # before the project exists. The numeric id stays in the policy and bindings.
  vault_name = { for key in keys(var.projects) : key => "ci-${replace(key, "/", "-")}" }
}

resource "vault_policy" "project_aws_read" {
  for_each = local.vault_projects

  name   = "${local.vault_name[each.key]}-aws-read"
  policy = <<-EOT
    path "kv/data/ci/production/project-${gitlab_project.this[each.key].id}/aws" {
      capabilities = ["read"]
    }
  EOT
}

resource "vault_jwt_auth_backend_role" "project" {
  for_each = local.vault_projects

  backend           = vault_jwt_auth_backend.gitlab.path
  role_name         = local.vault_name[each.key]
  role_type         = "jwt"
  bound_audiences   = [var.vault_incluster_url]
  user_claim        = "project_id"
  bound_claims_type = "string"
  bound_claims = {
    project_id    = tostring(gitlab_project.this[each.key].id)
    ref           = "main"
    ref_type      = "branch"
    ref_protected = "true"
  }
  token_policies          = [vault_policy.project_aws_read[each.key].name]
  token_no_default_policy = true
  token_ttl               = 600
  token_explicit_max_ttl  = 600

  # A role that trusts ref_protected=true must not exist before the protection does.
  depends_on = [gitlab_branch_protection.main]
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
