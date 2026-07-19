# Out-Of-Band Talos Bootstrap

This runbook brings up the Talos compute substrate, ARC runners, Zot cache, and
Kyverno image policy in dependency order. It is deliberately written as a
workstation-driven path: do not use an in-cluster runner to create the cluster
components that runner depends on.

This document is a procedure and safety contract. Adding or changing it does not
authorize live cluster mutation.

## Bootstrap Invariant

Keep admission policy from becoming a circular dependency:

1. A workstation with `talosctl` and `kubectl` controls Talos directly.
2. The Talos control plane reaches `Ready`.
3. ARC and Zot are applied out of band before any in-cluster repair path depends
   on first-party image admission.
4. Base and gate images are published, signed, mirrored, and verified by
   digest.
5. Kyverno first-party image verification is trusted in blocking enforcement
   only after the signed image chain exists and ARC plus Zot are excluded from
   that policy.

The order is not optional. Enforcing image admission before ARC, Zot, base
images, and gate images are known-good can deny the components needed to repair
the denial.

## Scope And Guardrails

- Run every bootstrap command from the workstation or another trusted
  out-of-cluster runner until ARC is online and proven.
- Do not run bootstrap from ARC while installing or repairing ARC itself.
- Do not depend on in-cluster components to repair Kyverno image verification
  during initial bootstrap.
- Keep the ARC namespace and Zot namespace outside image verification
  enforcement so the runner control plane and cache can restart during policy
  incidents. The ARC namespace in this repo is currently `arc-systems`; use the
  exact namespace present in the manifests when the policy is authored.
- Keep cluster secrets out of Vault-backed ESO during bootstrap. ARC GitHub App
  material and the Zot GHCR pull token must come from the out-of-band secret
  store until Vault and ESO are already live consumers.
- Treat all kubeconfigs, talosconfigs, GitHub App keys, GHCR tokens, SOPS age
  keys, and generated Talos secrets as sensitive. Keep them under `.s3/`, an
  approved encrypted store, or removable recovery media; never commit them.

## Required Inputs

- Workstation access to the management network.
- `talosctl` compatible with the cluster Talos version.
- `kubectl` compatible with the cluster Kubernetes version.
- Stage-0 Talos material: `secrets.yaml`, generated machine configs,
  `talosconfig`, and kubeconfig recovery path.
- Out-of-band cluster-secret material for:
  - ARC GitHub App credentials;
  - Zot authenticated GHCR pull token;
  - any SOPS or sealed-secrets keys needed to decrypt those bootstrap secrets.
- Repository revision containing the Talos machine configs, Flux bootstrap
  manifests, ARC manifests, Zot manifests, and reviewed Kyverno policy
  manifests.
- The exact signed base and gate image digests that must exist before
  enforcement.

## Phase 1: Workstation Preflight

1. Confirm the workstation is not relying on ARC:

   ```bash
   hostname
   talosctl version --client --short
   kubectl version --client=true
   ```

2. Confirm the sensitive local paths exist but do not print their contents:

   ```bash
   test -f .s3/configs/talosconfig
   test -f .s3/configs/kubeconfig
   test -f .s3/secrets/secrets.yaml
   ```

3. Point tools at the out-of-band credentials:

   ```bash
   export TALOSCONFIG=.s3/configs/talosconfig
   export KUBECONFIG=.s3/configs/kubeconfig
   ```

4. Confirm the target control-plane endpoints are the intended management IPs:

   ```bash
   talosctl config info
   kubectl config current-context
   ```

Stop if any command resolves to an unexpected cluster, empty endpoint, or
credential outside the approved bootstrap material.

## Phase 2: Talos Control Plane Ready

1. Apply or repair Talos machine configs from the workstation. Use the current
   repository bootstrap scripts or explicit `talosctl apply-config` commands
   approved for the maintenance window.

2. Bootstrap etcd once, from one control-plane node:

   ```bash
   talosctl bootstrap --nodes <bootstrap-control-plane-ip>
   ```

3. Wait for Talos health:

   ```bash
   talosctl health --nodes <control-plane-ip>
   ```

4. Fetch or refresh kubeconfig from Talos if needed:

   ```bash
   talosctl kubeconfig \
     --nodes <control-plane-ip> \
     --force .s3/configs/kubeconfig
   ```

5. Prove the Kubernetes API is reachable and Ready:

   ```bash
   kubectl get --raw=/readyz
   kubectl get nodes -o wide
   kubectl -n kube-system get pods
   ```

Do not apply ARC, Zot, or Kyverno until the API server is Ready from the
workstation. Do not depend on GitOps or ARC to repair an API server that is not
Ready yet.

## Phase 3: Install ARC And Zot Before In-Cluster Gates

Apply ARC, Zot, and Kyverno from the workstation or a trusted hosted runner.
During this phase, keep bootstrap repair paths outside image-verification
enforcement:

- first-party image verification is not trusted until Phase 6 confirms the
  current `[Deny]`/`Fail` posture;
- third-party image verification remains Audit-only;
- the ARC namespace and `zot-system` are excluded from image verification;
- ARC runner pods use rootless Podman or an equivalent non-privileged runtime;
- Zot pulls GHCR through authenticated credentials and is configured to mirror
  runtime manifests plus signature and attestation objects.

1. Apply the bootstrap secret material for ARC and Zot from the out-of-band
   store. Do not source it from Vault-backed ESO at this stage.

2. Apply ARC controller and scale-set manifests:

   ```bash
   kubectl apply -k clusters/talos-cluster/apps/actions-runner-controller
   kubectl apply -k clusters/talos-cluster/tenants/arc-systems
   kubectl apply -k clusters/talos-cluster/tenants/arc-runners
   ```

3. Apply the reviewed Zot manifests after its GHCR token exists. The Zot
   kustomization is authored in a later change; use its committed path when it
   exists rather than inventing a workstation-local manifest:

   ```bash
   kubectl apply -k <zot-kustomize-path>
   ```

4. Apply Kyverno engine and policy manifests from the reviewed repository
   posture:

   ```bash
   kubectl apply -k clusters/talos-cluster/apps/kyverno
   ```

5. Verify the posture before running any in-cluster gates:

   ```bash
   kubectl -n arc-systems get pods
   kubectl -n zot-system get pods
   kubectl -n kyverno get pods
   kubectl get clusterpolicy
   kubectl get validatingwebhookconfigurations | grep kyverno
   ```

Stop if first-party image verification is enforcing before the signed image
chain exists, or if the ARC/Zot namespaces are not excluded.

## Phase 4: Prove ARC And Zot

1. Run a smoke workflow on the ARC gate-check scale set. The job must prove:

   - GitHub minted OIDC for the run;
   - the runner is ephemeral;
   - container commands use rootless Podman, not privileged Docker-in-Docker.

2. Prove Zot can serve runtime image bytes by digest:

   ```bash
   skopeo inspect docker://<zot-ghcr-mirror>/<image>@sha256:<digest>
   ```

3. Prove Zot mirrors signature and attestation objects, not only runtime
   manifests:

   ```bash
   skopeo inspect docker://<zot-ghcr-mirror>/<image>:sha256-<digest>.sig
   skopeo list-tags docker://<zot-ghcr-mirror>/<image>
   ```

4. Record whether Kyverno resolves signatures through Zot or directly against
   GHCR. If it resolves directly against GHCR, GHCR availability remains an
   admission-time dependency until the later cache-agnostic proof is passed.

Do not proceed to enforcement if Zot has only mirrored runtime manifests. The
signature and attestation objects are separate OCI objects and must be available
to the verifier path that Kyverno actually uses.

## Phase 5: Publish And Verify Base Plus Gate Images

Kyverno enforcement waits for the signed image supply chain to exist.

Before relying on enforcing policy, prove all required base and gate images:

1. Each image is published by immutable digest in the public
   `ghcr.io/nwarila-platform/*` source namespace.
2. Each image digest is mirrored through Zot.
3. Each image signature verifies against the exact expected signer workflow
   identity.
4. SLSA provenance and required attestations verify against the same digest.
5. Required gate images can run from their digest on the ARC gate-check runner.

Use exact-image commands for the current digest set, for example:

```bash
cosign verify \
  --certificate-identity '<exact-signer-workflow-ref>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/nwarila-platform/<image>@sha256:<digest>

gh attestation verify \
  ghcr.io/nwarila-platform/<image>@sha256:<digest> \
  --repo nwarila-platform/<source-repo> \
  --signer-workflow '<exact-signer-workflow-ref>'
```

Do not replace these identity checks with organization-wide regular expressions
or tag checks. The runtime policy depends on digest plus exact signer identity.

## Phase 6: Verify Kyverno Enforcement

Only after Talos is Ready, ARC is proven, Zot is proven, and the base plus gate
image set exists by digest, verify that image verification is blocking for the
intended workload scope.

The Enforce change must preserve:

- ARC and `zot-system` namespace exclusions;
- the break-glass kubeconfig path from the workstation;
- exact signer workflow identity checks;
- digest-based image references;
- the documented Rekor and Fulcio availability posture.

> **POSTURE CHECK (2026-07-19).** First-party enforcement now lives on the single
> merged `ImageValidatingPolicy/verify-first-party`, NOT on a ClusterPolicy, and
> it is now at `[Deny]`/`Fail`. Step 4 below ("must fail admission") is
> meaningful when this command returns `[Deny] Fail`; if it does not, stop before
> trusting steps 3-5:
>
> ```bash
> kubectl get imagevalidatingpolicy verify-first-party \
>   -o jsonpath='{.spec.validationActions}{" "}{.spec.failurePolicy}{"\n"}'
> ```

1. Capture the pre-change policy and webhook posture:

   ```bash
   kubectl get imagevalidatingpolicy verify-first-party -o yaml > .s3/kyverno-policy-before.yaml
   kubectl get validatingwebhookconfiguration -o yaml > .s3/kyverno-webhook-before.yaml
   ```

2. Apply the reviewed manifest. Note this applies whatever posture is committed
   in git; verify the result before the admission tests:

   ```bash
   kubectl apply -k clusters/talos-cluster/apps/kyverno
   ```

3. Prove known-good signed images admit:

   ```bash
   kubectl apply -f <known-good-signed-pod.yaml>
   kubectl wait --for=condition=Ready pod/<known-good-pod> --timeout=120s
   ```

4. Prove an unsigned or wrong-identity image is denied:

   ```bash
   kubectl apply -f <known-bad-pod.yaml>
   ```

   This command must fail admission. If it succeeds, the policy is not enforcing
   the intended trust boundary.

5. Prove ARC and Zot still restart under the enforced posture:

   ```bash
   kubectl -n arc-systems rollout status deploy/<arc-controller-deployment> --timeout=120s
   kubectl -n zot-system rollout status deploy/<zot-deployment> --timeout=120s
   ```

Stop and use break-glass if the known-good image is denied, if ARC or Zot cannot
restart, or if the wrong-identity image is admitted.

## Break-Glass

Break-glass is a workstation operation using the out-of-band kubeconfig. It is
for admission outages, bad policy rollouts, bad digest sets, or public Sigstore
availability failures that block legitimate cluster work.

Prefer the narrowest reversible action that restores admission:

1. For a first-party IVP incident, suspend the policy reconciler and delete the
   merged IVP. The current IVP is `[Deny]`/`Fail`; suspend plus delete is the
   narrow immediate mitigation for a bad policy or stale-pin incident.

   ```bash
   flux suspend kustomization kyverno-policies -n flux-system
   kubectl delete imagevalidatingpolicy verify-first-party
   ```

   The `flux` CLI is NOT installed on every operator workstation (it is absent on
   `kasm-nuc01`). Use the kubectl equivalent when it is missing — suspending is a
   field write on the Kustomization, so it needs no extra tooling:

   ```bash
   kubectl patch kustomization kyverno-policies -n flux-system \
     --type=merge -p '{"spec":{"suspend":true}}'
   kubectl delete imagevalidatingpolicy verify-first-party
   ```

   Suspend BEFORE deleting: `kyverno-policies` reconciles every 10m with
   `prune: true`, so deleting the policy without suspending lets Flux re-apply it
   and the incident resumes.

   For a legacy `verifyImages` incident, delete
   `clusterpolicy/verify-image-signatures-enforced` instead after suspending the
   same Kustomization.

2. If the webhook itself is unavailable or blocks the patch, make the webhook
   non-blocking:

   ```bash
   kubectl patch validatingwebhookconfiguration <kyverno-webhook-name> \
     --type=json \
     -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]'
   ```

3. If admission is still wedged, temporarily scale the Kyverno admission
   controller down from the workstation:

   ```bash
   kubectl -n kyverno scale deploy <kyverno-admission-controller> --replicas=0
   ```

4. Restore the last known-good policy or digest set.

5. Re-enable Kyverno, return the webhook and policy to the reviewed posture, and
   repeat the known-good and known-bad admission tests before leaving the
   incident.

Record the incident cause, exact commands, timestamps, and final policy state.
Do not leave the cluster in a silent permissive state after the repair window.

## Rekor And Fulcio Availability

Keyless verification requires the trust material needed to validate the
certificate chain and Rekor inclusion proof. In the current posture, a
verification failure must fail closed for normal workloads; it must not silently
admit unverified images.

> **Updated 2026-07-18.** The online Rekor/Fulcio/CT/TUF dependency this section
> was written against is no longer on the admission path: the first-party
> attestors verify OFFLINE against pinned Sigstore keys (#333), which is what
> removed the 2026-07-14 brick vector. A Sigstore *outage* therefore no longer
> blocks first-party admission. A *stale pin* now fails closed under the current
> `verify-first-party` `[Deny]`/`Fail` IVP posture.

That fail-closed posture is acceptable only because break-glass remains
out-of-band and ARC/Zot stay excluded. **The outage scenario below is retired:**
with offline pins (#333) a public-good Sigstore outage no longer prevents
first-party admission, so there is no Sigstore-availability reason to reach for
break-glass. The failure modes that can block admission now are (a) a STALE PIN
after a Sigstore key rotation, and (b) the Kyverno v1.18.2 IVP handoff defect
that intermittently yields `policy not evaluated` (see ADR-0027's 2026-07-18
amendment). For either, break-glass means suspending the
`kyverno-policies` Kustomization and deleting
`ImageValidatingPolicy/verify-first-party` — NOT restoring the legacy
ClusterPolicy, which is Audit and retired by PR-C2.

Reducing this availability exposure is a separate hardening task: pin the
Sigstore TUF root, cache Rekor proofs where supported by the chosen verifier
path, and prove the GHCR-blocked admission test with Zot and Rekor still
reachable.

## Pass Criteria

The bootstrap path is complete only when all of these are true and recorded:

- Talos control plane is Ready from the workstation.
- ARC scale sets are online, ephemeral, and running rootless Podman.
- Zot serves runtime manifests plus signature and attestation objects by digest.
- Kyverno starts with the single merged `verify-first-party` IVP in
  `[Deny]`/`Fail`.
- The ARC namespace and `zot-system` remain excluded from image verification.
- Base and gate image digests exist in GHCR, mirror through Zot, and verify
  against exact signer workflow identities.
- A known-good signed workload admits under the current `[Deny]`/`Fail` posture.
- A known-bad or wrong-identity workload is denied under the current
  `[Deny]`/`Fail` posture.
- Break-glass has been tested from the workstation kubeconfig.
- No ARC, Zot, or cluster secret bootstrap step depended on Vault-backed ESO or
  on an in-cluster runner before those services were already live.
