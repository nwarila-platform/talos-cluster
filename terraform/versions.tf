terraform {
  # Pin Terraform exactly per org ADR 0005.
  required_version = "= 1.15.1"

  required_providers {
    # Add provider blocks here. Each must use exact `=` pinning.
    # Example:
    #   proxmox = {
    #     source  = "bpg/proxmox"
    #     version = "= 0.50.0"
    #   }
  }
}
