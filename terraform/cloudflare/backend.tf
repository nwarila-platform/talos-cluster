# Same state bucket as terraform/gitlab-vault, its own key: the edge (a tunnel
# and DNS records) changes on a different cadence from GitLab's configuration
# and needs a different credential, so the two roots never share a plan.
terraform {
  backend "s3" {
    bucket              = "793496711039-terraform"
    key                 = "nwarila-platform/talos-cluster/cloudflare.tfstate"
    region              = "us-east-1"
    encrypt             = true
    use_lockfile        = true
    allowed_account_ids = ["793496711039"]
  }
}
