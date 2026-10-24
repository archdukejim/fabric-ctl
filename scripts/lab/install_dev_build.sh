#!/bin/bash
# -----------------------------------------------------------------------
# Install a development build of fabric on a lab VM (manual 3.1.5.9): the .deb built from a branch, then an
# unattended setup from a settings file. Pending images (config/images.lock.yaml) are built by setup on the VM.
# Run from Git Bash on gaming-23 (Windows OpenSSH and the lab key; no Python needed here):
#
#   scripts/lab/install_dev_build.sh 10.88.0.10 <fabricctl_….deb> tests/lab/dhcp_vars.yaml [<pre-setup.sh>]
#
# <pre-setup.sh>, lab-only and optional: a script run as root on the VM after the package is installed and before
# setup (a diagnostic wrapper, 2.3.10.11.16). The first admin's password is generated on the VM (/root/lab-admin-pw,
# 0600) and never leaves it. Only the lab's 10.88.0.0/24 is accepted. Every file it removes is a literal path on the
# VM, never one built from a variable (2.3.10.11.16). Restore the VM's checkpoint `clean` to run it again (3.1.5.5).
# -----------------------------------------------------------------------
set -euo pipefail
[ $# -eq 3 ] || [ $# -eq 4 ] || { sed -n '3,13p' "$0"; exit 2; }
VM="$1"; DEB="$2"; VARS="$3"; PRE="${4:-}"
case "$VM" in 10.88.0.*) ;; *) echo "refused: $VM is not a lab address (10.88.0.0/24, manual 3.1.5.1)" >&2; exit 2 ;; esac
[ -f "$DEB" ] || { echo "refused: no package at $DEB" >&2; exit 2; }
[ -f "$VARS" ] || { echo "refused: no settings file at $VARS" >&2; exit 2; }
[ -z "$PRE" ] || [ -f "$PRE" ] || { echo "refused: no pre-setup script at $PRE" >&2; exit 2; }
SSH=(-i "$HOME/.ssh/g23_lab" -o "UserKnownHostsFile=$HOME/fabric-lab/known_hosts" -o BatchMode=yes -o ConnectTimeout=20)
on() { ssh "${SSH[@]}" "labadmin@$VM" "$@" 2>&1 | grep -v "post-quantum\|store now\|upgraded. See" || true; }

echo "--- copying $(basename "$DEB") and the settings to $VM"
scp -q "${SSH[@]}" "$DEB" "labadmin@$VM:/tmp/fabricctl.deb"
scp -q "${SSH[@]}" "$VARS" "labadmin@$VM:/tmp/lab-vars.yaml"
echo "--- apt install, and the first admin's password generated on the VM"
on "sudo install -m 0600 /tmp/lab-vars.yaml /root/lab-vars.yaml && rm -f -- /tmp/lab-vars.yaml
    sudo sh -c 'umask 077; [ -s /root/lab-admin-pw ] || printf \"Lab-%s\n\" \"\$(openssl rand -hex 12)\" > /root/lab-admin-pw'
    sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/fabricctl.deb >/dev/null
    dpkg-query -W -f='\${Package} \${Version}\n' fabricctl"
if [ -n "$PRE" ]; then
    echo "--- the lab-only pre-setup script $(basename "$PRE")"
    scp -q "${SSH[@]}" "$PRE" "labadmin@$VM:/tmp/lab-pre-setup.sh"
    on "sudo bash /tmp/lab-pre-setup.sh"
fi
echo "--- setup (unattended; it runs as fabric-setup.service, so a dropped connection does not stop it)"
on "sudo fabricctl setup --file /root/lab-vars.yaml --non-interactive --yes --approve all \
    --admin-password-file /root/lab-admin-pw > /tmp/lab-setup.log 2>&1; echo \"setup exit \$?\"; tail -5 /tmp/lab-setup.log"
if ssh "${SSH[@]}" "labadmin@$VM" "grep -q 'fabric is ready' /tmp/lab-setup.log" 2>/dev/null; then
    echo "fabric is ready on $VM"
else
    echo "setup did not finish: sudo fabricctl setup on $VM follows it; its log is /opt/fabric/config/setup-run.log" >&2
    exit 1
fi
