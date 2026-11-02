#!/bin/bash
# -----------------------------------------------------------------------
# Lab only (manual 3.1.5.9, 2.3.10.11.16): run on a lab VM as root after the package is installed and before setup,
# as install_dev_build.sh's pre-setup script. It makes the installed samba/run_converge append the converge code's
# whole error output (not only its last line) to /root/converge-errors.log (0600, root only). That output can hold
# a secret, so the file never leaves the VM: read only its traceback's frame lines there, and restore the VM's
# checkpoint `clean` afterwards (3.1.5.5). Refuses anywhere but a lab VM (hostname g23-vm-*).
# -----------------------------------------------------------------------
set -euo pipefail
case "$(hostname)" in g23-vm-*) ;; *) echo "refused: not a lab VM" >&2; exit 2 ;; esac
F=/usr/lib/fabricctl/fabric/lib/fabriclib/samba/run_converge.py
[ -f "$F" ] || { echo "refused: no $F (is the package installed?)" >&2; exit 2; }
grep -q "converge-errors.log" "$F" && { echo "already wrapped"; exit 0; }
python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
src = open(path).read()
anchor = "    if res.returncode != 0:\n"
keep = ("    if res.returncode != 0:  # lab only: keep the whole error output (scripts/lab/keep_converge_errors.sh)\n"
        "        import os\n"
        "        fd = os.open('/root/converge-errors.log', os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)\n"
        "        os.write(fd, ((res.stderr or '') + os.linesep + '---' + os.linesep).encode())\n"
        "        os.close(fd)\n")
if src.count(anchor) != 1:
    sys.exit("refused: run_converge.py is not as expected")
open(path, "w").write(src.replace(anchor, keep + anchor.replace("    if", "    if", 1)))
PY
echo "run_converge keeps its errors in /root/converge-errors.log"
