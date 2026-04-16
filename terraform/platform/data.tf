data "terraform_remote_state" "bootstrap" {
  backend = "s3"
  config = {
    bucket = "793496711039-terraform"
    key    = "nwarila-platform/talos-cluster/bootstrap.tfstate"
    region = "us-east-1"
  }
}
