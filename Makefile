# =============================================================================
# TDNHQ-TALCL01 — Talos Kubernetes Cluster Makefile
# =============================================================================
SHELL := /bin/bash
.DEFAULT_GOAL := help

# -----------------------------------------------------------------------------
# Targets
# -----------------------------------------------------------------------------

.PHONY: help init generate validate apply apply-insecure bootstrap upgrade \
        health kubeconfig s3-push s3-pull clean reset

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# -- Setup --------------------------------------------------------------------

init: ## Verify prerequisites (talosctl, kubectl)
	@echo "==> Checking prerequisites..."
	@command -v talosctl >/dev/null 2>&1 || { \
		echo "talosctl not found. Install from https://www.talos.dev/latest/talos-guides/install/talosctl/"; \
		exit 1; \
	}
	@command -v kubectl >/dev/null 2>&1 || { \
		echo "kubectl not found. Install from https://kubernetes.io/docs/tasks/tools/"; \
		exit 1; \
	}
	@echo "    talosctl: $$(talosctl version --client --short 2>/dev/null)"
	@echo "    kubectl:  $$(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"
	@echo "==> All prerequisites satisfied."

# -- Config Generation --------------------------------------------------------

generate: ## Generate machine configs from patches + secrets
	@bash scripts/generate.sh

validate: ## Validate generated machine configs
	@echo "==> Validating machine configs..."
	@shopt -s nullglob; \
	cp_configs=(.s3/generated/controlplane/*.yaml); \
	wk_configs=(.s3/generated/worker/*.yaml); \
	if [ $${#cp_configs[@]} -eq 0 ] || [ $${#wk_configs[@]} -eq 0 ]; then \
		echo "==> ERROR: No generated configs in .s3/generated/{controlplane,worker}/."; \
		echo "    Run 'make generate' first."; \
		exit 1; \
	fi; \
	failed=0; \
	for f in "$${cp_configs[@]}" "$${wk_configs[@]}"; do \
		echo "    $${f}..."; \
		talosctl validate --config "$${f}" --mode metal --strict || failed=1; \
	done; \
	if [ "$$failed" -eq 1 ]; then \
		echo "==> VALIDATION FAILED"; exit 1; \
	fi; \
	echo "==> All configs valid!"

# -- Deployment ---------------------------------------------------------------

apply: validate ## Apply configs to nodes (NODES="HOST1 HOST2" to target specific)
ifdef NODES
	@bash scripts/apply.sh $(NODES)
else
	@bash scripts/apply.sh
endif

apply-insecure: validate ## Apply configs in insecure mode (initial provisioning)
ifdef NODES
	@bash scripts/apply.sh --insecure $(NODES)
else
	@bash scripts/apply.sh --insecure
endif

bootstrap: ## Bootstrap cluster — run ONCE on initial setup
	@bash scripts/bootstrap.sh

upgrade: ## Rolling Talos upgrade (NODES="HOST1 HOST2" to target; YES=1 to skip confirm)
	@bash scripts/upgrade.sh $(if $(YES),--yes) $(NODES)

# -- Operations ---------------------------------------------------------------

health: ## Run cluster health checks
	@bash scripts/health.sh

kubeconfig: ## Fetch kubeconfig from cluster
	@source cluster/config.env && \
	talosctl kubeconfig \
		--talosconfig .s3/configs/talosconfig \
		--nodes "$${BOOTSTRAP_NODE##*:}" \
		--force \
		.s3/configs/kubeconfig
	@echo "==> Kubeconfig saved to .s3/configs/kubeconfig"

# -- S3 Sync -----------------------------------------------------------------

s3-push: ## Push local .s3/ to AWS S3
	@bash scripts/s3-sync.sh push

s3-pull: ## Pull from AWS S3 to local .s3/
	@bash scripts/s3-sync.sh pull

# -- Cleanup ------------------------------------------------------------------

clean: ## Remove generated configs/client configs; keep secrets bundle
	@echo "==> Cleaning generated configs and local client configs..."
	@rm -rf .s3/generated/
	@rm -f .s3/configs/talosconfig
	@rm -f .s3/configs/kubeconfig
	@echo "==> Clean complete. Talos secrets bundle preserved."

reset: ## Full reset — remove ALL generated files including secrets
	@echo "WARNING: This will delete ALL secrets and generated configs!"
	@read -p "Type 'yes' to confirm: " confirm && \
	if [ "$$confirm" = "yes" ]; then \
		rm -rf .s3/secrets/ .s3/configs/ .s3/generated/; \
		echo "==> Full reset complete."; \
	else \
		echo "Aborted."; \
	fi
