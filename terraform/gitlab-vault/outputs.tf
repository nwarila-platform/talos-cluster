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
