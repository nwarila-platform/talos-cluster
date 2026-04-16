provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      "talos-cluster:managed-by" = "terraform"
      "talos-cluster:stack"      = "platform"
      "talos-cluster:repo"       = "nwarila-platform/talos-cluster"
    }
  }
}

// cloudflare, github, and vault providers are configured via environment
// variables in the trusted Terraform Platform Apply workflow.
provider "cloudflare" {}
provider "github" {}
provider "vault" {}
