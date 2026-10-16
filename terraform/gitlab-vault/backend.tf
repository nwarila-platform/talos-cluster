# State lives in the existing Terraform state bucket (SSE-S3, versioned). The
# S3 lock file replaces DynamoDB. Credentials come from the environment
# (AWS_PROFILE=mgmt-admin via SSO today; an OIDC role from the pipeline later).
terraform {
  backend "s3" {
    bucket       = "793496711039-terraform"
    key          = "nwarila-platform/talos-cluster/gitlab-vault.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
    # Refuse to touch state with credentials for any other account.
    allowed_account_ids = ["793496711039"]
  }
}
