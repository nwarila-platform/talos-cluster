# Release Gates

PRs to `main` must pass:

- `make ci` (Terraform fmt/init/validate/test, TFLint, terraform-docs
  diff, Diátaxis docs layout, OPA tests)
- Reusable lint gates (actionlint, shellcheck, yamllint, ruff,
  markdownlint)
- Reusable IaC security gates (Trivy, Gitleaks, zizmor)

All gates run via `NWarila/terraform-template` reusable workflows and
must be SHA-pinned per the contract.
