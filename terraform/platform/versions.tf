terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.2"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.3"
    }
  }
}
