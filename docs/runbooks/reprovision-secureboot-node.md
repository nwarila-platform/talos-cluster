# Reprovision A SecureBoot+TPM Talos Node

This runbook is for reprovisioning one Talos node onto the SecureBoot installer
and TPM-backed STATE/EPHEMERAL encryption. It is deliberately one-node-at-a-time:
drain, verify, install, prove recovery, then move to the next node.

Do not hand-build maintenance ISOs. Use only:

```bash
scripts/build-maintenance-iso.sh <node>
```

That script pins the static `ip=` kernel argument to `eno1` and refuses an empty
device field before it posts a schematic to Talos Factory.

## Scope And Guardrails

- Reprovision one node only.
- Do not run `talosctl apply-config` until the maintenance boot has proven
  SecureBoot is actually enabled.
- Do not seal disk encryption against a node whose maintenance boot reports
  `SECUREBOOT: false`.
- Reboots and power cycles are owner-physical operations. There is no remote KVM
  or IPMI path yet.
- Confirm the Talos host firewall includes trustd port `50001`; the CI guard for
  that rule is the durable check.

## Preflight

1. Confirm the node is healthy enough to remove from service:

   ```bash
   kubectl get nodes
   talosctl --talosconfig .s3/configs/talosconfig -e <node-ip> -n <node-ip> health
   ```

2. Confirm current recovery material exists and is usable:

   - Stage 0: `secrets.yaml`, `age.agekey`, `talosconfig`, generated configs.
   - Latest etcd snapshot and manifest.
   - Any workload/PV backup needed before evicting workloads from this node.

3. Drain or otherwise evacuate workloads from the node using the current
   operational procedure for this cluster.

4. Confirm the node patch in this repo targets the intended install disk and
   uses the fleet NIC bus path:

   ```yaml
   deviceSelector:
     busPath: "0000:00:1f.6"
   ```

## Build The Maintenance ISO

1. Build the ISO URL with the repo helper:

   ```bash
   scripts/build-maintenance-iso.sh <node>
   ```

2. Confirm the printed kernel argument has this shape:

   ```text
   ip=<nodeIP>::10.69.112.1:24:<node>:eno1:off
   ```

   The sixth field is the device. It must be `eno1`.

3. Use the printed `metal-amd64-secureboot.iso` URL. The schematic must include:

   - the `installer-secureboot`/SecureBoot Talos variant
   - the current repo `TALOS_VERSION`
   - the current repo schematic extensions from `TALOS_SCHEMATIC_ID`
   - `talos.halt_if_installed=0`
   - the pinned `ip=...:eno1:off` static network argument

The w3 canary failed repeatedly when a hand-built ISO used `ip=...:w3::off`.
That empty device field caused the kernel to apply the address to multiple
interfaces, including `bond0`, which created duplicate default routes. DNS,
NTP, and trustd traffic from the node failed until the ISO was rebuilt with
`eno1` pinned. Never hand-assemble or manually POST this schematic.

## Firmware Steps

These are physical-owner steps at the machine:

1. Enable TPM / Intel PTT.
2. Enable Secure Boot.
3. Put Secure Boot in setup mode.
4. Boot the Talos maintenance ISO.
5. At the Talos boot menu, press `Esc` and choose:

   ```text
   Enroll Secure Boot keys: auto
   ```

Keys being present in firmware is not the same as enforcement. The Talos
maintenance boot must show SecureBoot enabled before the encrypted install.

The GPU framebuffer may disappear once SecureBoot module signature enforcement
is active. Larger console text is cosmetic and does not mean storage, NIC, or
Talos drivers are missing.

## Maintenance-Mode Verification

Use maintenance-mode commands with `-i` after the subcommand:

```bash
talosctl --talosconfig .s3/configs/talosconfig -e <node-ip> -n <node-ip> version -i
talosctl --talosconfig .s3/configs/talosconfig -e <node-ip> -n <node-ip> get links eno1 -o yaml -i
talosctl --talosconfig .s3/configs/talosconfig -e <node-ip> -n <node-ip> get securitystate -o yaml -i
```

Confirm `securitystate` reports:

```text
SECUREBOOT: true
```

Stop if it does not. Do not apply a TPM/PCR-7 sealed config against the wrong
SecureBoot state.

Maintenance mode has a smaller API surface than a configured Talos node. These
commands are known traps:

- `talosctl dmesg -i` is not available.
- `talosctl time -i` is not available.
- `talosctl disks -i` is not available.

To estimate whether the node clock is sane, inspect resource metadata
`created`/`updated` timestamps from resources that do work in maintenance mode.

## Install Config Requirements

The node config used for install must contain:

- install image:

  ```text
  factory.talos.dev/installer-secureboot/<schematic>:<TALOS_VERSION>
  ```

- STATE and EPHEMERAL `VolumeConfig` documents using:

  ```yaml
  encryption:
    provider: luks2
    keys:
      - slot: 0
        tpm: {}
  ```

The TPM key is sealed to PCR 7, so the pre-apply SecureBoot gate is not optional.

## Install And Postchecks

1. Apply the generated node config only after the SecureBoot gate passes.
2. Reboot or power-cycle physically as needed.
3. Confirm the node rejoins:

   ```bash
   kubectl get nodes
   talosctl --talosconfig .s3/configs/talosconfig -e <node-ip> -n <node-ip> health
   talosctl --talosconfig .s3/configs/talosconfig -e <node-ip> -n <node-ip> get securitystate
   talosctl --talosconfig .s3/configs/talosconfig -e <node-ip> -n <node-ip> get volumes
   ```

4. Confirm the host firewall still exposes Talos API and trustd management ports
   from the allowed management source:

   - `50000` apid
   - `50001` trustd

5. Restore scheduling only after the node is healthy and manageable.

## Recommendation

Build DHCP/netboot on the provisioning subnet before rolling through the
remaining fleet. DHCP/netboot removes the per-node static `ip=` kernel cmdline
and the USB-at-the-rack loop entirely.
