terraform {
  required_version = ">= 1.15.0"

  required_providers {
    gitlab = {
      source  = "gitlabhq/gitlab"
      version = "19.5.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "5.13.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "3.3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "3.3.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "6.69.1"
    }
  }
}
