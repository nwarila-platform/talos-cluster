SHELL := /bin/bash
# Every recipe runs in bash's privileged mode: BASH_ENV and ENV are not sourced, SHELLOPTS/BASHOPTS
# (an inherited xtrace), CDPATH and GLOBIGNORE in the environment are ignored and exported shell
# functions are not imported — so no inherited shell state can print or redirect a credential
# before a driver's own `set +x`. The drivers are started by absolute path, in the same mode.
.SHELLFLAGS := -p -c
.DEFAULT_GOAL := help

.PHONY: help init generate validate apply apply-insecure bootstrap platform \
	vault-init cloudflare-plan cloudflare cloudflare-verify gitlab-vault-plan gitlab-vault vault-configure \
	vault-seed-aws keycloak selftest health kubeconfig

help:
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "%-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: ## Check local tools required for a rebuild
	@for command in talosctl kubectl helm openssl jq terraform vault aws curl flock shellcheck yamllint actionlint python3; do \
		command -v "$$command" >/dev/null || { echo "missing: $$command"; exit 1; }; \
	done
	@python3 -I -c "import yaml" >/dev/null 2>&1 || { \
		echo "missing: python3 PyYAML (needed by make validate)"; exit 1; \
	}
	@source cluster/config.env; \
	actual="$$(talosctl version --client --short | awk '/Talos v/ {print $$2; exit}')"; \
	[[ "$$actual" == "$${TALOS_VERSION}" ]] || { \
		echo "talosctl $${TALOS_VERSION} required; found $${actual:-unknown}"; exit 1; \
	}

generate: ## Generate six machine configs and local Talos credentials
	@bash scripts/generate.sh

validate: ## Validate scripts, manifests, Terraform, and generated configs when present
	@bash scripts/validate.sh

selftest: ## Run the self-tests: vault-init, keycloak and health against stubs, the unsealer against local Vault servers, validate against mutants
	@bash scripts/tests/selftest-vault-init.sh
	@bash scripts/tests/selftest-vault-unsealer.sh
	@bash scripts/tests/selftest-keycloak.sh
	@bash scripts/tests/selftest-health.sh
	@bash scripts/tests/selftest-validate.sh

apply: validate ## Apply configs; requires CONFIRM_REBUILD=TDNHQ-TALCL01
	@bash scripts/apply.sh $(NODES)

apply-insecure: validate ## Initial apply; requires CONFIRM_REBUILD=TDNHQ-TALCL01
	@bash scripts/apply.sh --insecure $(NODES)

bootstrap: ## Bootstrap etcd once; requires CONFIRM_REBUILD=TDNHQ-TALCL01
	@bash scripts/bootstrap.sh

platform: ## Install the pinned Calico, Longhorn, Argo CD, Vault, cert-manager, CloudNativePG and Keycloak operator charts and the Keycloak manifests
	@bash scripts/install-platform.sh

vault-init: ## Initialize and unseal the new Vault raft cluster
	@bash scripts/vault-init.sh

cloudflare-plan: ## Preflight, then save a reviewed plan for the GitLab edge (tunnel, DNS); needs CLOUDFLARE_API_TOKEN, AWS_PROFILE
	@/bin/bash -p scripts/cloudflare.sh plan

cloudflare: ## Apply the saved edge plan and write the connector's token file for the host; needs the same plus CONFIRM_REBUILD=TDNHQ-TALCL01
	@/bin/bash -p scripts/cloudflare.sh apply

cloudflare-verify: ## Prove the public path: tunnel healthy, discovery document and JWKS served through Cloudflare
	@/bin/bash -p scripts/cloudflare.sh verify

gitlab-vault-plan: ## Preflight, then save a reviewed plan for GitLab, Vault, AWS and the runner; needs GITLAB_TOKEN, VAULT_TOKEN, AWS_PROFILE
	@/bin/bash -p scripts/gitlab-vault.sh plan

gitlab-vault: ## Apply the saved plan, then prove convergence, non-expiring runner tokens and an online runner; needs the same three plus CONFIRM_REBUILD=TDNHQ-TALCL01
	@/bin/bash -p scripts/gitlab-vault.sh apply

keycloak: ## Create the realm Secret from .state/keycloak, wait for Keycloak, import the tcn realm (AD federation, GitLab client); requires CONFIRM_REBUILD=TDNHQ-TALCL01
	@bash scripts/keycloak.sh

vault-configure: ## (superseded by gitlab-vault) Configure one project's GitLab JWT auth in Vault by hand
	@bash scripts/configure-vault-gitlab.sh

vault-seed-aws: ## Seed a dedicated static AWS PoC credential from environment
	@bash scripts/seed-aws-poc.sh

health: ## Check Talos, Kubernetes, pods, and Helm releases
	@bash scripts/health.sh

kubeconfig: ## Refresh the local kubeconfig
	@source cluster/config.env; \
	state_root="$${STATE_DIR_OVERRIDE:-$${PWD}/$${STATE_DIR}}"; \
	talosctl kubeconfig --talosconfig "$${state_root}/configs/talosconfig" \
		--endpoints "$${BOOTSTRAP_NODE##*:}" --nodes "$${BOOTSTRAP_NODE##*:}" \
		--force "$${state_root}/configs/kubeconfig"
