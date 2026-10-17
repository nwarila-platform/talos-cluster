#!/usr/bin/env bash
# LDAPS certificates for the two domain controllers, from the cluster's Vault PKI (make dc-ldaps;
# run it again to renew, before the 90 days are up). Per DC, over SSH as Administrator: generate a
# P-384 key and CSR ON the DC (the key never leaves it), sign it with Vault
# (pki-int-linux/sign/tcn-server), trust the PKI root and issuing CA on the DC, install the
# certificate, tell AD DS to load it, then prove LDAPS with a real bind as svc-keycloak.
# Needs the Vault init file and the svc-keycloak password in .state, the kubeconfig, and the DC SSH key.
# Undo per DC: remove the cert from Cert:\LocalMachine\My, the root from Root, the issuing CA from CA.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
K=(-o BatchMode=yes -o IdentitiesOnly=yes -i "$HOME/.ssh/nwarila-ec2-key")
VADDR=https://10.69.112.63:30200
KUBECONFIG="$R/.state/configs/kubeconfig" kubectl -n keycloak get configmap root-ca -o jsonpath='{.data.ca\.crt}' > "$W/root.crt"
# The encoded command is expanded here on purpose: it is the whole program the DC runs.
# shellcheck disable=SC2029
dcps() { local dc="$1"; shift; local e; e=$(iconv -t UTF-16LE | base64 -w0); ssh "${K[@]}" "Administrator@$dc" "powershell -NoProfile -NonInteractive -EncodedCommand $e" < /dev/null 2>/dev/null | tr -d '\r'; }
for entry in tcnhq-dc01:10.69.112.4 tcnhq-dc02:10.69.112.5; do
  host=${entry%%:*}; ip=${entry##*:}; fqdn="$host.tcn.trinitytechnicalservices.com"
  echo "== $fqdn ($ip)"
  # 1. key + CSR on the DC
  dcps "$ip" > "$W/$host.csr" <<PS
\$ErrorActionPreference = "Stop"
\$dir = "C:\\ProgramData\\tcn-ldaps"; New-Item -ItemType Directory -Force -Path \$dir | Out-Null
\$lines = @('[Version]', 'Signature="\$Windows NT\$"', '[NewRequest]', 'Subject = "CN=$fqdn"', 'KeyAlgorithm = ECDSA_P384', 'KeyLength = 384', 'MachineKeySet = TRUE', 'Exportable = FALSE', 'ProviderName = "Microsoft Software Key Storage Provider"', 'RequestType = PKCS10', 'HashAlgorithm = sha384', '[EnhancedKeyUsageExtension]', 'OID=1.3.6.1.5.5.7.3.1', '[Extensions]', '2.5.29.17 = "{text}"', '_continue_ = "dns=$fqdn&"', '_continue_ = "ipaddress=$ip"')
Set-Content -Path "\$dir\\req.inf" -Value \$lines -Encoding ASCII
Remove-Item -Force -ErrorAction SilentlyContinue "\$dir\\req.csr"
\$o = & certreq.exe -q -new -machine "\$dir\\req.inf" "\$dir\\req.csr" 2>&1
if (\$LASTEXITCODE -ne 0) { Write-Error ("certreq -new: " + (\$o -join " ")) }
Get-Content "\$dir\\req.csr" -Raw
PS
  openssl req -in "$W/$host.csr" -noout || { echo "STOP: no CSR from $host"; exit 1; }
  # 2. Vault signs it
  jq -n --rawfile csr "$W/$host.csr" --arg cn "$fqdn" --arg ip "$ip" '{csr: $csr, common_name: $cn, alt_names: $cn, ip_sans: $ip, ttl: "2160h", format: "pem"}' > "$W/$host.json"
  { printf 'header = "X-Vault-Token: %s"\nheader = "Content-Type: application/json"\ndata = "@%s"\n' "$(jq -r .root_token "$R/.state/vault/init.json")" "$W/$host.json"; } \
    | env -i PATH="$PATH" HOME="$HOME" curl --disable -sS --max-time 30 --cacert "$R/.state/vault/tls/ca.crt" -K - "$VADDR/v1/pki-int-linux/sign/tcn-server" > "$W/$host.out"
  jq -r '.data.certificate' "$W/$host.out" > "$W/ldaps.crt"; jq -r '.data.issuing_ca' "$W/$host.out" > "$W/issuing.crt"
  openssl verify -CAfile "$W/root.crt" -untrusted "$W/issuing.crt" "$W/ldaps.crt" >/dev/null || { echo "STOP: signed cert does not verify"; exit 1; }
  # 3. trust + install + reload
  scp -q "${K[@]}" "$W/root.crt" "$W/issuing.crt" "$W/ldaps.crt" "Administrator@$ip:C:/ProgramData/tcn-ldaps/"
  dcps "$ip" <<'PS'
$ErrorActionPreference = "Stop"
$dir = "C:\ProgramData\tcn-ldaps"
Import-Certificate -FilePath "$dir\root.crt" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath "$dir\issuing.crt" -CertStoreLocation Cert:\LocalMachine\CA | Out-Null
$o = & certreq.exe -q -accept -machine "$dir\ldaps.crt" 2>&1
if ($LASTEXITCODE -ne 0) { Write-Error ("certreq -accept: " + ($o -join " ")) }
Set-Content -Path "$dir\renew.ldf" -Value @("dn:", "changetype: modify", "add: renewServerCertificate", "renewServerCertificate: 1", "-", "") -Encoding ASCII
& ldifde.exe -i -f "$dir\renew.ldf" | Out-Null
$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1" }
Write-Output ("installed: " + ($c.Subject -join ",") + " privatekey=" + ($c.HasPrivateKey -join ","))
PS
  # 4. prove it: the DC serves the certificate on 636 and a real bind succeeds over LDAPS
  sleep 5
  echo | openssl s_client -connect "$ip:636" -CAfile "$W/root.crt" -verify_return_error 2>/dev/null | grep -E 'Verify return code' || true
  LDAPTLS_CACERT="$W/root.crt" ldapwhoami -x -H "ldaps://$ip" -D "CN=svc-keycloak,OU=Domain Service Accounts,DC=tcn,DC=trinitytechnicalservices,DC=com" -y <(tr -d '\n' < "$R/.state/keycloak/svc-keycloak.password")
done
echo "LDAPS ready on both DCs; Keycloak's AD provider uses ldaps:// to both by name."
