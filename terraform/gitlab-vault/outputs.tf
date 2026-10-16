output "runner_id" {
  description = "GitLab id of the cluster's instance runner."
  value       = gitlab_user_runner.cluster.id
}

output "project_ids" {
  description = "GitLab project ids by <group>/<project>; GITLAB_PROJECT_ID for make vault-seed-aws."
  value       = { for key, project in gitlab_project.this : key => project.id }
}

output "project_urls" {
  description = "Web URLs of the onboarded projects."
  value       = { for key, project in gitlab_project.this : key => project.web_url }
}

output "gitlab_url" {
  description = "GitLab URL the root was applied against."
  value       = var.gitlab_url
}

output "aws_role_arns" {
  description = "IAM role ARNs by <group>/<project> for projects with aws_access."
  value       = { for key, role in aws_iam_role.project : key => role.arn }
}

output "aws_oidc_provider_arn" {
  description = "ARN of the IAM identity provider that trusts GitLab's ID tokens."
  value       = aws_iam_openid_connect_provider.gitlab.arn
}
