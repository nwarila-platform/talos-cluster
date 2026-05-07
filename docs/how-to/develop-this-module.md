# Develop this module

## Local setup

Use the devcontainer in [`nwarila/terraform-template/.devcontainer`](https://github.com/NWarila/terraform-template/tree/main/.devcontainer)
or install the same pinned tools manually:

- Terraform 1.15.1
- TFLint 0.59.1
- terraform-docs 0.20.0
- OPA 1.10.0
- Python 3.12 with `pyyaml`, `ruff`, `yamllint`, `zizmor`

## The development loop

```sh
make fmt        # format Terraform
make ci         # run every gate
make docs       # regenerate docs/reference/terraform.md
```

## Before opening a PR

```sh
make ci
```

If `make ci` is green locally, the reusable validation workflow will be
green in CI.
