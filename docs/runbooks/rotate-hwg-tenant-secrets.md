# Rotate HWG Tenant Secrets

Stock Traefik v3.7.10 must `get/list/watch` Secrets in every watched namespace
and waits for its Secret informer cache before the Kubernetes Ingress provider
becomes operational. For `hwg-1268831311`, this exposes `Secret/ghcr-pull` and
`Secret/hwg-1268831311-gitops-source-auth` to the `traefik-hwg` ServiceAccount.

This is an accepted, bounded, rotatable risk—not least privilege. There are no
Traefik RoleBindings in nwp or nwa namespaces. The proxy runs under restricted
PSS, and its egress is limited to the Kubernetes API plus explicitly labelled
hwg pods on TCP 8080. Relocating the Secrets, maintaining a no-informer fork, or
changing tenants to Gateway API were rejected for this MVP.

Never print, decode, diff, or capture either Kubernetes Secret during rotation.
Use metadata and resource versions as evidence.

## Rotate `ghcr-pull`

1. Create the replacement package-read credential and a fresh Docker config in
   a private temporary file outside the repository.
2. Record the current Kubernetes Secret resource version without reading data:

   ```bash
   kubectl get secret ghcr-pull -n hwg-1268831311 \
     -o jsonpath='{.metadata.resourceVersion}{"\n"}'
   ```

3. With a short-lived Vault token, replace the Vault source value. Do not place
   the JSON on the command line or in shell history:

   ```bash
   vault kv put secret/platform/org-pull/hwg/ghcr-pull \
     .dockerconfigjson=@/private/path/to/dockerconfig.json
   ```

4. Wait for `VaultStaticSecret/ghcr-pull` to report a successful sync and for
   the Kubernetes Secret resource version to change. Verify a disposable image
   pull in the hwg tenant, then revoke the old credential at its issuer.
5. Securely remove the temporary file according to the operator workstation's
   credential-handling procedure.

## Rotate `hwg-1268831311-gitops-source-auth`

This Secret contains a short-lived GitHub App installation token. The
`source-rotator-hwg` CronJob refreshes its Vault source on a schedule; VSO then
copies it into Kubernetes. To force a fresh token without exposing it:

```bash
kubectl get secret hwg-1268831311-gitops-source-auth -n hwg-1268831311 \
  -o jsonpath='{.metadata.resourceVersion}{"\n"}'
job_name="source-rotator-hwg-manual-$(date +%s)"
kubectl create job -n source-rotator \
  --from=cronjob/source-rotator-hwg "${job_name}"
kubectl wait -n source-rotator --for=condition=complete \
  "job/${job_name}" --timeout=10m
kubectl logs -n source-rotator "job/${job_name}"
```

The log must report the hwg tenant as successful and no tenant failure. Wait for
`VaultStaticSecret/hwg-1268831311-gitops-source-auth` to report a successful
sync and confirm the Secret resource version changed. Then reconcile the tenant
GitRepository and prove it becomes Ready. Installation tokens expire within an
hour; if the underlying GitHub App private key is suspected compromised, rotate
that key using the organization-onboarding custody procedure before triggering
this job.

Finally, recheck `Deployment/traefik-hwg` remains 2/2 Ready. Rotation must not
require granting the proxy any additional RBAC or network access.
