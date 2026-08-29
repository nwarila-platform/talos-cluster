# Operate HWG Self-Service Ingress

This runbook completes and verifies the one-time cft3a-MVP wildcard cutover for
the already-onboarded `hwg-1268831311` tenant. It does not onboard a new tenant:
`cluster/deploy-repo-overrides.sh` remains the deliberate trust gate for that
separate operation.

## Preconditions

- The cft3a-MVP Git change is merged and Flux sees its exact merged revision.
- `cloudflared` credentials remain healthy; do not expose `cert.pem` or tunnel
  credentials in command output or incident evidence.
- The operator host has the Cloudflare `cert.pem` needed by `cloudflared tunnel
  route dns`.
- Record the existing wildcard A record before changing it. Keep the full
  answer, TTL, and provider-side record identity in the change evidence:

  ```bash
  dig +noall +answer '*.theherowarsguys.com' A
  ```

## Reconcile And Prove The Connector Rollout

Reconcile the root and both child inventories, then wait for the proxy and the
connector rollout. The connector pod-template annotation must be
`config-revision: cft3a-mvp-v1`; projected ConfigMap changes do not make
cloudflared reload its ingress rules.

```bash
flux reconcile kustomization flux-system -n flux-system --with-source
flux reconcile kustomization traefik-hwg -n flux-system
flux reconcile kustomization kyverno-policies -n flux-system
kubectl rollout status deployment/traefik-hwg -n traefik-hwg --timeout=10m
kubectl rollout status deployment/cloudflared-hwg -n cloudflared-hwg --timeout=10m
kubectl get pods -n traefik-hwg -l nwarila.io/tunnel-proxy=hwg -o wide
kubectl get pods -n cloudflared-hwg \
  -l app.kubernetes.io/name=cloudflared,app.kubernetes.io/instance=hwg -o wide
```

Both Deployments must report two Ready pods. Confirm the hand-authored class has
the stock controller string and no default-class annotation:

```bash
kubectl get ingressclass cf-tunnel-hwg -o json | jq -e '
  .spec.controller == "traefik.io/ingress-controller" and
  (.metadata.annotations["ingressclass.kubernetes.io/is-default-class"] == null)
'
```

Before changing wildcard DNS or testing a wildcard-backed host, prove the two
more-specific routes survived the connector rollout. Add a unique query value
to avoid reusing a cached response:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  "https://canary-hwg.theherowarsguys.com/?cft3a=$(date +%s)"
curl -fsS -o /tmp/cft3a-hello-response -w '%{http_code}\n' \
  "https://hello.theherowarsguys.com/?cft3a=$(date +%s)"
rg -Fx 'hello-hwg-v1' /tmp/cft3a-hello-response
```

The first status must be `418`. The second status must be `200` and the body
marker must match.

## Replace The Wildcard DNS Record

Run exactly this planner-owned command. The wildcard is quoted to prevent shell
expansion, and `--overwrite-dns` is mandatory because the wildcard A record
already exists:

```bash
cloudflared tunnel route dns --overwrite-dns 81379ca9-d323-4e95-8f7b-11f8937956e2 '*.theherowarsguys.com'
```

This changes only the wildcard owner name. The exact `canary-hwg` and `hello`
records remain more specific.

## Autonomous Proof

In the existing tenant deploy repository, deploy a second app with only:

1. `nwarila.io/tunnel-exposed: "true"` on its pod template; and
2. an Ingress using `cf-tunnel-hwg`, a freshly invented
   `*.theherowarsguys.com` hostname, at least one HTTP path, and a Service
   backend whose port is numeric `8080`.

Do not edit this platform repository, tunnel ConfigMap, DNS, or any network
policy for the app. Wait for the tenant Flux Kustomization, then make an
uncached external request and record its real status and body marker. Re-run the
canary and hello checks afterward; they must remain 418 and 200 respectively.

Also verify cft2 interoperation with separate objects: the hwg class is admitted
and `cf-tunnel-nwp` is denied. Do not combine a bad hostname and wrong class in
one denial probe because validating webhooks execute in parallel.

## Rollback

Revert the cft3a-MVP commits and reconcile Flux. That prunes the proxy, class,
RBAC, policies, and inherited target allow while restoring the previous
cloudflared route and rollout revision. Restore the recorded wildcard A record
through its authoritative DNS provider; the tunnel command cannot reconstruct
the old record. Re-prove canary 418 and hello 200 after rollback.
