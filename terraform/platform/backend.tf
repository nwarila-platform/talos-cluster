terraform {
  backend "s3" {
    bucket       = "793496711039-terraform"
    key          = "nwarila-platform/talos-cluster/platform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
