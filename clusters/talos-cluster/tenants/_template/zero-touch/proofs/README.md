# Render proofs

Render-only evidence for Phase 2 lives here. These files are generated from the
template and are not referenced by Flux.

Regenerate the herowars proof from the repository root:

```sh
kubectl kustomize clusters/talos-cluster/tenants/_template/zero-touch/examples/herowars \
  > clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-render.yaml
kubectl kustomize clusters/talos-cluster/tenants/herowars \
  > clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-live-envelope.yaml
printf '\n---\n' >> clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-live-envelope.yaml
cat clusters/talos-cluster/apps/herowars/kustomization-flux.yaml \
  >> clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-live-envelope.yaml
printf '\n---\n' >> clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-live-envelope.yaml
cat clusters/talos-cluster/apps/herowars/gitrepository.yaml \
  >> clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-live-envelope.yaml
git diff --no-index -- \
  clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-live-envelope.yaml \
  clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-render.yaml \
  > clusters/talos-cluster/tenants/_template/zero-touch/proofs/herowars-vs-live.diff || true
```

The comparable live bundle includes the hand-authored tenant envelope and the
hand-authored app GitRepository/Kustomization. It intentionally excludes the
SOPS GitHub App auth Secret because the reusable template references that
per-org auth Secret but does not own or render secret material.
