provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      "talos-cluster:managed-by" = "terraform"
      "talos-cluster:stack"      = "bootstrap"
      "talos-cluster:repo"       = "nwarila-platform/talos-cluster"
    }
  }
}
