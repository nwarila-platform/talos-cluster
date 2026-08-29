# cft3a-MVP — implementation handoff

**Implemented:** 2026-08-29

**Baseline:** `origin/main@858e28d`

**Branch:** `build/cft3a-mvp`

## Delivered

- Traefik v3.7.10 / chart v41.2.0 in `traefik-hwg`, two replicas with
  soft cross-node spread, a ClusterIP Service, and Kubernetes Ingress as the
  only enabled provider.
- Hand-authored non-default `IngressClass/cf-tunnel-hwg` and split RBAC. The
  cluster role contains only `ingressclasses` and `nodes`; the only tenant Role
  is in `hwg-1268831311` and contains `ingresses`, `services`, `endpointslices`,
  and the accepted `secrets` informer access.
- Exact network contracts: cloudflared to Traefik TCP 8000 on both sides,
  Traefik to `kube-apiserver` TCP 6443, and proxy-to-opted-in-pod TCP 8080 on
  both sides.
- The inherited tenant opt-in label contract
  `nwarila.io/tunnel-exposed: "true"` and a fail-closed admission requirement
  for numeric Service backend port 8080 with at least one HTTP path.
- The wildcard tunnel route after the preserved canary and hello rules, plus
  the required connector pod-template revision bump to `cft3a-mvp-v1`.
- A minimal orthogonal hostname policy and core Kyverno fixture suite.
- The exact planner-owned wildcard DNS command, rollout order, autonomous proof,
  and rollback in `docs/runbooks/operate-hwg-self-service-ingress.md`.
- The accepted tenant-Secret exposure and rotation procedure in
  `docs/runbooks/rotate-hwg-tenant-secrets.md`.

No second application is platform-owned. The autonomous proof must be created
in the existing tenant deploy repository using only the label and Ingress; a
platform manifest would invalidate the MVP claim.

## Local Evidence

- Root, proxy-child, and hwg-tenant Kustomize renders: PASS, including the
  rendered namespace check and desired-build inventory discovery.
- Helm v41.2.0 render assertions: PASS (exact tag+digest image, ClusterIP,
  Service 80 to pod web port 8000, Kubernetes-Ingress-only provider family,
  class and watched-namespace arguments, two replicas, no host network or PVC).
- Rendered class/RBAC/CNP assertions: PASS (default annotation absent; Secrets
  and Nodes present; no nwp/nwa binding; 8000/6443/8080 on the exact legs).
- cft1/cft3-lite preservation assertion: PASS (existing canary and hello routes
  and policy legs are unchanged; only the required wildcard, proxy egress, and
  connector revision were added).
- Existing `restrict-tunnel-binding` fixtures: PASS, 18 cases.
- New `restrict-tunnel-hostnames` core fixtures: PASS, 17 cases, including
  numeric 8080 admission and cft2-precondition pass-through.
- Every local repository guard and self-test from `validate.yaml`: PASS.
- Talos throwaway generation plus strict validation: PASS for all six node
  configs; throwaway secrets and generated files were removed afterward.
- ShellCheck, changed-YAML lint, pinned gitleaks 8.30.1, actionlint 1.7.10,
  generic changed-file hooks, and image/firewall/maintenance guards: PASS.
- Workflow health: expected exit 1 with only `org-adr-auto-sync.yaml` red; run
  32706137992 contains the exact terminal signature `A sync_token secret is
  required to push sync branches and open PRs.`

The aggregate `pre-commit run --all-files` wrapper could not install its
gitleaks hook because this environment has no Go executable (and its default
cache path is read-only). This is a tooling limitation, not an implementation
deviation: the pinned gitleaks release and every other constituent hook were
run directly and passed.

## Deviations

None from REV.B. Live rollout, DNS mutation, and public HTTP probes were not run
locally because REV.B assigns them to the planner after merge.

## Post-Merge Owner Gates

The implementation is complete; live and external gates necessarily remain
planner-owned after merge:

1. Reconcile and observe two Ready Traefik pods and two newly rolled Ready
   cloudflared pods.
2. Confirm `IngressClass/cf-tunnel-hwg` has no default annotation.
3. Prove canary 418 and hello 200 before wildcard testing.
4. Record the old wildcard A record, then run the documented quoted
   `cloudflared tunnel route dns --overwrite-dns` command.
5. Deploy the second app from the existing hwg tenant repo using only the
   opt-in label and a new valid Ingress; record an uncached public response.
6. Re-prove cft2 class isolation, canary 418, and hello 200.

## PF-5

PF-5 is booked as TD-0022 and contains only the explicitly deferred MVP debt:
the exhaustive fixture matrix, cross-class controller proof, cross-org
dataplane negative, named workflow-health evaluator, PDB/hard spread, and PF-4
hostname-conflict enforcement.

## Rollback

Revert the cft3a-MVP commits and reconcile Flux. The child prune boundary
removes the proxy/class/RBAC/CNP inventory, the policy inventory prunes the new
policy, and tenant renders remove the inherited target allow. Restore the
recorded wildcard A record at the authoritative provider. The pre-existing
canary and hello routes and their policy rules are preserved throughout.
