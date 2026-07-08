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
3. ARC and Zot are applied out of band while Kyverno image verification is
   non-blocking.
4. Base and gate images are published, signed, mirrored, and verified by
   digest.
5. Kyverno image verification moves to blocking enforcement only after the
   signed image chain exists and ARC plus Zot are excluded from that policy.

The order is not optional. Enforcing image admission before ARC, Zot, base
images, and gate images are known-good can deny the components needed to repair
the denial.

## Scope And Guardrails

- Run every bootstrap command from the workstation or another trusted
  out-of-cluster runner until ARC is online and proven.
- Do not run bootstrap from ARC while installing or repairing ARC itself.
- Do not make Kyverno image verification blocking during initial bootstrap.
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
  manifests, ARC manifests, Zot manifests, and Kyverno Audit/Ignore manifests.
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

## Phase 3: Install ARC And Zot With Non-Blocking Kyverno

Apply ARC, Zot, and Kyverno from the workstation or a trusted hosted runner.
During this phase, image verification must be observable but non-blocking:

- policy action is Audit;
- the image-verification webhook `failurePolicy` is `Ignore`;
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

4. Apply Kyverno engine and policy manifests only in the bootstrap-safe posture:

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

Stop if image verification is already enforcing, if the webhook is not
`failurePolicy=Ignore`, or if the ARC/Zot namespaces are not excluded.

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

Before flipping any policy to Enforce, prove all required base and gate images:

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

## Phase 6: Flip Kyverno To Enforce

Only after Talos is Ready, ARC is proven, Zot is proven, and the base plus gate
image set exists by digest, move image verification to blocking enforcement for
the intended workload scope.

The Enforce change must preserve:

- ARC and `zot-system` namespace exclusions;
- the break-glass kubeconfig path from the workstation;
- exact signer workflow identity checks;
- digest-based image references;
- the documented Rekor and Fulcio availability posture.

1. Capture the pre-change policy and webhook posture:

   ```bash
   kubectl get clusterpolicy <image-policy-name> -o yaml > .s3/kyverno-policy-before.yaml
   kubectl get validatingwebhookconfiguration <kyverno-webhook-name> -o yaml > .s3/kyverno-webhook-before.yaml
   ```

2. Apply the reviewed Enforce manifest:

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

1. Patch image verification back to Audit:

   ```bash
   kubectl patch clusterpolicy <image-policy-name> \
     --type=merge \
     -p '{"spec":{"validationFailureAction":"Audit"}}'
   ```

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
certificate chain and Rekor inclusion proof. When Kyverno is in Enforce, a
Rekor, Fulcio, CT log, TUF-root, or network failure that prevents verification
must fail closed for normal workloads. It must not silently admit unverified
images.

That fail-closed posture is acceptable only because break-glass remains
out-of-band and ARC/Zot stay excluded. If the public-good Sigstore services are
unavailable and legitimate workloads cannot admit, use break-glass to restore
Audit or temporarily disable the webhook, then return to Enforce after
verification succeeds again.

Reducing this availability exposure is a separate hardening task: pin the
Sigstore TUF root, cache Rekor proofs where supported by the chosen verifier
path, and prove the GHCR-blocked admission test with Zot and Rekor still
reachable.

## Pass Criteria

The bootstrap path is complete only when all of these are true and recorded:

- Talos control plane is Ready from the workstation.
- ARC scale sets are online, ephemeral, and running rootless Podman.
- Zot serves runtime manifests plus signature and attestation objects by digest.
- Kyverno starts in Audit with `failurePolicy=Ignore`.
- The ARC namespace and `zot-system` remain excluded from image verification.
- Base and gate image digests exist in GHCR, mirror through Zot, and verify
  against exact signer workflow identities.
- Kyverno is flipped to Enforce only after those digests exist and are verified.
- A known-good signed workload admits under Enforce.
- A known-bad or wrong-identity workload is denied under Enforce.
- Break-glass has been tested from the workstation kubeconfig.
- No ARC, Zot, or cluster secret bootstrap step depended on Vault-backed ESO or
  on an in-cluster runner before those services were already live.
