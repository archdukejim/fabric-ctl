#!/bin/bash
# The generated 802.1X scripts checked on Windows PowerShell 5.1 (manual 3.1.5.12, decision 2.1.11.4), from Git Bash on
# gaming-23: generated here, copied to a running Windows VM, parsed and their commands looked up there, never run. Nothing
# about 802.1X is proven by this: that needs real hardware (2.3.11.5).
# usage: [WIN=10.88.0.42] bash tests/lab/dot1x_scripts.sh     (g23-vm-w11-1 by default; the VM is already up)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WIN="${WIN:-10.88.0.42}"
SSH=(-i "$HOME/.ssh/g23_lab" -o "UserKnownHostsFile=$HOME/fabric-lab/known_hosts" -o BatchMode=yes -o ConnectTimeout=20)
PY=$(command -v python3 || command -v python) || { echo "FAIL no python here"; exit 1; }

WORK=$(mktemp -d) || exit 1
case "$WORK" in /tmp/*|*/Temp/*) ;; *) echo "FAIL unexpected scratch folder $WORK"; exit 1 ;; esac
trap 'rm -rf "${WORK:?}"' EXIT

# a root CA for the scripts to embed, made for this run; only its public certificate leaves this folder
mkdir "$WORK/files"
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=fabric test root" \
    -keyout "$(cygpath -m "$WORK/root.key")" -out "$(cygpath -m "$WORK/root.pem")" 2>/dev/null || { echo "FAIL no test root CA"; exit 1; }
"$PY" "$HERE/dot1x_scripts_make.py" "$WORK/root.pem" "$WORK/files" || exit 1

REMOTE='C:\Windows\Temp\fabric-dot1x-check'
ssh "${SSH[@]}" "labadmin@$WIN" "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$REMOTE' | Out-Null\"" ||
    { echo "FAIL no way into $WIN"; exit 1; }
scp -q "${SSH[@]}" "$WORK"/files/* "$HERE/dot1x_scripts_check.ps1" "labadmin@$WIN:C:/Windows/Temp/fabric-dot1x-check/" ||
    { echo "FAIL copying to $WIN"; exit 1; }
ssh "${SSH[@]}" "labadmin@$WIN" "powershell -NoProfile -ExecutionPolicy Bypass -File $REMOTE\\dot1x_scripts_check.ps1 -Dir $REMOTE"
rc=$?
ssh "${SSH[@]}" "labadmin@$WIN" "powershell -NoProfile -Command \"Remove-Item -Recurse -Force -Path '$REMOTE'\"" ||
    echo "note: $REMOTE is left on $WIN"
echo "dot1x_scripts rc=$rc"
exit "$rc"
