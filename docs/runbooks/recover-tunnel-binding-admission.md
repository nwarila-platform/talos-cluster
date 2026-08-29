# Recover Tunnel-Binding Admission

This runbook recovers tenant Ingress writes if the fail-closed tunnel-binding
admission policy must be rolled back or Kyverno is unavailable.

The source policy file is
`clusters/talos-cluster/apps/kyverno/policies/restrict-tunnel-binding.yaml`.
It creates `ValidatingPolicy/restrict-tunnel-binding`. There is no IngressClass
object in that file.

## Normal Rollback

Use the GitOps path whenever Kyverno and admission are available.

1. Revert the commit that introduced the policy file and its entry in
   `clusters/talos-cluster/apps/kyverno/policies/kustomization.yaml`.
2. Merge the revert.
3. Reconcile the source and policy Kustomization:

   ```bash
   flux reconcile source git flux-system -n flux-system
   flux reconcile kustomization kyverno-policies -n flux-system --with-source
   ```

4. Confirm Flux pruning removed the policy resource:

   ```bash
   kubectl get validatingpolicy restrict-tunnel-binding
   ```

The command must return `NotFound`. Do not delete or edit the live policy as a
substitute for the Git revert; Flux would recreate it from the repository.

## Emergency: Kyverno Unavailable And Ingress Writes Blocked

Use this procedure only when all of the following are true:

- Kyverno itself is unavailable;
- `failurePolicy: Fail` is causing tenant Ingress writes to fail before policy
  evaluation; and
- waiting for normal Kyverno recovery or the Git revert plus Flux prune is not
  operationally acceptable.

Removing this webhook entry disables the binding control until Kyverno
recreates them. Record the incident and have an owner present.

1. Confirm the error is a webhook availability failure, not an intentional
   policy denial. Capture Kyverno pod state and the exact admission error:

   ```bash
   kubectl -n kyverno get pods
   kubectl get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg \
     -o json | jq -r '.webhooks[] | select(.name | contains("restrict-tunnel")) | .name'
   ```

   Expected entries:

   ```text
   vpol.validate.kyverno.svc-fail-finegrained-restrict-tunnel-binding
   ```

2. Save the current generated configuration as incident evidence:

   ```bash
   incident_dir="$(mktemp -d)"
   kubectl get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg \
     -o yaml >"${incident_dir}/kyverno-resource-validating-webhook-cfg.before-emergency.yaml"
   echo "Saved webhook evidence under ${incident_dir}"
   ```

3. Remove only the generated policy entry:

   ```bash
   webhook_config=kyverno-resource-validating-webhook-cfg
   webhook_name=vpol.validate.kyverno.svc-fail-finegrained-restrict-tunnel-binding
   webhook_index="$(
     kubectl get validatingwebhookconfiguration "${webhook_config}" -o json |
     jq -er --arg name "${webhook_name}" \
       '.webhooks | to_entries[] | select(.value.name == $name) | .key'
   )"
   kubectl patch validatingwebhookconfiguration "${webhook_config}" \
     --type=json \
     -p="[{\"op\":\"remove\",\"path\":\"/webhooks/${webhook_index}\"}]"
   ```

4. Verify the entry is absent and retry only the blocked tenant Ingress
   operation:

   ```bash
   kubectl get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg \
     -o json | jq -e '
       [.webhooks[].name | select(contains("restrict-tunnel"))] | length == 0
     '
   ```

## Restore Enforcement

Restore Kyverno health first. If the policy should remain enabled, reconcile it
so Kyverno regenerates the webhook entry:

```bash
flux reconcile kustomization kyverno -n flux-system
flux reconcile kustomization kyverno-policies -n flux-system --with-source
kubectl get validatingpolicy restrict-tunnel-binding \
  -o jsonpath='{.status.conditionStatus.ready}{"\n"}'
```

The readiness value must be `true`. Confirm the generated webhook entry is
present again before closing the incident. If the policy is being retired,
complete the normal Git revert and Flux-prune procedure instead.
