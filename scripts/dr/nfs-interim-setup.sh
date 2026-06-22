#!/usr/bin/env bash
# Run as root inside WSL:
#   wsl.exe -d Ubuntu-24.04 -u root -- bash /mnt/c/.../scripts/dr/nfs-interim-setup.sh
#
# Reproduces the interim DR Stage 1 NFS backup server and installs the WSL
# boot command that starts it whenever the Ubuntu-24.04 distro starts.

set -Eeuo pipefail

readonly EXPORT_DIR="/srv/nfs/backup"
readonly EXPORT_CIDR="10.69.112.0/24"
readonly EXPORT_OPTIONS="rw,async,no_subtree_check,no_root_squash"
readonly EXPORT_LINE="${EXPORT_DIR} ${EXPORT_CIDR}(${EXPORT_OPTIONS})"
readonly START_HELPER="/usr/local/sbin/nwarila-nfs-interim-start"
readonly WSL_CONF="/etc/wsl.conf"
readonly WSL_BOOT_COMMAND="${START_HELPER}"
readonly POLICY_RC="/usr/sbin/policy-rc.d"

policy_backup=""
policy_created="false"

log() {
  printf '==> %s\n' "$*"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    printf 'ERROR: run this script as root inside WSL.\n' >&2
    exit 1
  fi
}

install_policy_guard() {
  log "Installing temporary policy-rc.d guard for WSL package configuration"
  if [ -e "${POLICY_RC}" ] || [ -L "${POLICY_RC}" ]; then
    policy_backup="${POLICY_RC}.nfs-interim-backup.$$"
    mv "${POLICY_RC}" "${policy_backup}"
  else
    policy_created="true"
  fi

  cat >"${POLICY_RC}" <<'POLICY_EOF'
#!/bin/sh
exit 101
POLICY_EOF
  chmod 0755 "${POLICY_RC}"
}

restore_policy_guard() {
  if [ -n "${policy_backup}" ] && [ -e "${policy_backup}" ]; then
    mv -f "${policy_backup}" "${POLICY_RC}"
  elif [ "${policy_created}" = "true" ]; then
    rm -f "${POLICY_RC}"
  fi
}

repair_and_install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  install_policy_guard
  trap restore_policy_guard EXIT

  log "Repairing any half-configured packages"
  dpkg --configure -a
  apt-get -f install -y

  log "Installing NFS server packages"
  apt-get update
  apt-get install -y --no-install-recommends nfs-kernel-server nfs-common rpcbind
  dpkg --configure -a
}

write_start_helper() {
  log "Writing ${START_HELPER}"
  cat >"${START_HELPER}" <<HELPER_EOF
#!/usr/bin/env bash
set -Eeuo pipefail

readonly EXPORT_DIR="${EXPORT_DIR}"
readonly EXPORT_LINE="${EXPORT_LINE}"

mkdir -p /proc/fs/nfsd /run/rpcbind "\${EXPORT_DIR}"
chmod 1777 "\${EXPORT_DIR}"
printf '%s\n' "\${EXPORT_LINE}" >/etc/exports

if ! mountpoint -q /proc/fs/nfsd; then
  mount -t nfsd nfsd /proc/fs/nfsd
fi

if ! pgrep -x rpcbind >/dev/null 2>&1; then
  rpcbind -w
fi

exportfs -ra
rpc.nfsd 8

if ! pgrep -x rpc.mountd >/dev/null 2>&1; then
  rpc.mountd
fi
HELPER_EOF
  chmod 0755 "${START_HELPER}"
}

merge_wsl_conf_boot_command() {
  local tmp
  tmp="$(mktemp)"

  log "Merging WSL boot command into ${WSL_CONF}"
  if [ ! -f "${WSL_CONF}" ]; then
    printf '[boot]\ncommand = %s\n' "${WSL_BOOT_COMMAND}" >"${WSL_CONF}"
    return
  fi

  awk -v command="${WSL_BOOT_COMMAND}" '
    BEGIN {
      in_boot = 0
      boot_seen = 0
      command_written = 0
    }

    /^\[[^]]+\][[:space:]]*$/ {
      if (in_boot && !command_written) {
        print "command = " command
        command_written = 1
      }

      in_boot = ($0 ~ /^\[boot\][[:space:]]*$/)
      if (in_boot) {
        boot_seen = 1
        command_written = 0
      }

      print
      next
    }

    {
      if (in_boot && $0 ~ /^[[:space:]]*command[[:space:]]*=/) {
        if (!command_written) {
          print "command = " command
          command_written = 1
        }
        next
      }

      print
    }

    END {
      if (in_boot && !command_written) {
        print "command = " command
      } else if (!boot_seen) {
        print ""
        print "[boot]"
        print "command = " command
      }
    }
  ' "${WSL_CONF}" >"${tmp}"

  install -m 0644 "${tmp}" "${WSL_CONF}"
  rm -f "${tmp}"
}

print_boot_section() {
  log "Final WSL [boot] section"
  awk '
    /^\[boot\][[:space:]]*$/ { in_boot = 1; print; next }
    /^\[[^]]+\][[:space:]]*$/ { if (in_boot) exit; next }
    in_boot { print }
  ' "${WSL_CONF}"
}

main() {
  require_root
  repair_and_install_packages
  write_start_helper

  log "Starting interim NFS server"
  "${START_HELPER}"

  merge_wsl_conf_boot_command
  print_boot_section

  log "Interim NFS server setup complete"
}

main "$@"