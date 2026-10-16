# GitLab CI -> AWS without a stored credential: IAM trusts GitLab as an OpenID
# Connect identity provider, and each project with aws_access gets a role that
# only ID tokens from that project's protected main branch can assume. The issuer must
# be publicly reachable (terraform/cloudflare); the driver's preflight proves
# that before this provider is created. Adding a project to AWS = aws_access
# on its var.projects entry.
# local.gitlab_host is defined in runner.tf.
locals {
  aws_projects  = { for key, project in var.projects : key => project if project.aws_access }
  aws_role_name = { for key in keys(var.projects) : key => "gitlab_${replace(key, "/", "_")}" }
}

data "aws_caller_identity" "current" {}

resource "aws_iam_openid_connect_provider" "gitlab" {
  url            = var.gitlab_url
  client_id_list = [var.aws_oidc_audience]
  # No thumbprint_list: IAM retrieves and keeps the issuer's top intermediate
  # CA thumbprint itself (provider documentation), which is Cloudflare's edge
  # certificate chain for this hostname.

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "project" {
  for_each = local.aws_projects

  name                 = local.aws_role_name[each.key]
  description          = "GitLab CI for ${each.key}: ID tokens from branch main only"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.gitlab.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.gitlab_host}:aud" = var.aws_oidc_audience
          # The project's ID-token subject carries ref_protected (set on the
          # project in projects.tf), so a main that was unprotected at job
          # time cannot assume the role either.
          "${local.gitlab_host}:sub" = "project_path:${each.key}:ref_type:branch:ref:main:ref_protected:true"
        }
      }
    }]
  })

  # The sub claim pins main, and main must be protected before a role trusts it.
  depends_on = [gitlab_branch_protection.main]
}

# The proof permission: write and read one SSM parameter path that belongs to
# the project and nothing else. Real permissions are separate, reviewed policies.
resource "aws_iam_role_policy" "project_ssm_poc" {
  for_each = local.aws_projects

  name = "ssm-poc"
  # The role NAME is known at plan time; its id is not, and the driver's
  # preflight needs a known value to prove containment.
  role = aws_iam_role.project[each.key].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:PutParameter", "ssm:GetParameter"]
      Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/gitlab/poc/${each.key}/*"
    }]
  })
}

# Jobs build their role ARN from these two instance-level variables and
# CI_PROJECT_PATH; neither value is secret.
resource "gitlab_instance_variable" "aws_account_id" {
  key       = "AWS_ACCOUNT_ID"
  value     = data.aws_caller_identity.current.account_id
  protected = false
  masked    = false
}

resource "gitlab_instance_variable" "aws_region" {
  key       = "AWS_REGION"
  value     = var.aws_region
  protected = false
  masked    = false
}
