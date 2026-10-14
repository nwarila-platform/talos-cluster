SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help init generate validate apply apply-insecure bootstrap platform \
	vault-init vault-configure vault-seed-aws health kubeconfig

help:
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "%-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: ## Check local tools required for a rebuild
	@for command in talosctl kubectl helm openssl jq shellcheck python3; do \
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

validate: ## Validate scripts, manifests, and generated configs when present
	@bash scripts/validate.sh

apply: validate ## Apply configs; requires CONFIRM_REBUILD=TDNHQ-TALCL01
	@bash scripts/apply.sh $(NODES)

apply-insecure: validate ## Initial apply; requires CONFIRM_REBUILD=TDNHQ-TALCL01
	@bash scripts/apply.sh --insecure $(NODES)

bootstrap: ## Bootstrap etcd once; requires CONFIRM_REBUILD=TDNHQ-TALCL01
	@bash scripts/bootstrap.sh

platform: ## Install pinned Calico, Longhorn, Argo CD, and Vault charts
	@bash scripts/install-platform.sh

vault-init: ## Initialize and unseal the new Vault raft cluster
	@bash scripts/vault-init.sh

vault-configure: ## Configure project-scoped GitLab JWT auth in Vault
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
