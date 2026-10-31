import json
import os
import subprocess

from fabriclib.common.restore_original import restore_original
from fabriclib.consent.plan_member import KEPT_FILES, KEYTAB, RECORD
from fabriclib.setup.common.apply_host_managed import apply_host_managed
from fabriclib.setup.common.sssd_sockets import restore_sockets


def undo_member(config_dir, manage_units=True):
    """Purpose: undo the `member` host change (manual 1.2.9.5, 1.6.11.8): the host is no longer a member of its
             domain. Each file fabric changed goes back as it was (common/keep_original), the keytab goes, PAM's sss
             (and mkhomedir, when fabric turned it on) and sss in NSS are off again, sudo's alternative as it was,
             sssd stopped when fabric enabled it (else restarted), sssd's socket units as they were before fabric
             masked them (RECORD's "sockets", 2.1.6.95; their failures cleared), and fabric's management of the host
             removed (its
             SSH and DNS drop-ins and its lines in /etc/pam.d/sshd, manual 1.6.11.11). The packages stay.
    Inputs:  config_dir — the install's config folder (the kept copies and RECORD); manage_units — run
             pam-auth-update, update-alternatives and systemctl, and remove fabric's management (False in tests).
    Returns: list of str, what was done (empty when fabric never made the host a member).
    Fails:   OSError writing a file or reading RECORD; SetupError should pam_localuser be needed (never, to remove);
             a failing command is ignored (a package may be gone).
    Feeds:   undo/undo_group (`fabricctl setup --undo member`), setup/uninstall."""
    record = os.path.join(config_dir, RECORD)
    done = []
    for path in KEPT_FILES:
        how = restore_original(path, config_dir)
        if how:
            done.append(f"{path}: {'put back as it was' if how == 'restored' else 'removed (fabric added it)'}")
    if not os.path.exists(record):
        return done
    with open(record) as f:
        before = json.load(f)
    if os.path.exists(KEYTAB) and not any(KEYTAB in d for d in done):     # no record of it: fabric's copy goes
        os.remove(KEYTAB)
        done.append(f"{KEYTAB} removed")
    if manage_units:
        done += apply_host_managed({}, False)
        off = [p for p in ("sss", "mkhomedir") if p not in (before.get("pam") or [])]
        if off:
            subprocess.run(["pam-auth-update", "--disable", *off], capture_output=True)
            done.append(f"PAM: {' and '.join(off)} off")
        if before.get("sudo") and os.path.realpath("/etc/alternatives/sudo") != os.path.realpath(before["sudo"]):
            subprocess.run(["update-alternatives", "--set", "sudo", before["sudo"]], capture_output=True)
            done.append(f"sudo: {before['sudo']} again")
        if before.get("sssd_enabled"):
            subprocess.run(["systemctl", "restart", "sssd"], capture_output=True)
            done.append("sssd restarted with the host's own configuration")
        else:
            subprocess.run(["systemctl", "disable", "--now", "sssd"], capture_output=True)
            done.append("sssd stopped and disabled (fabric had enabled it)")
        subprocess.run(["systemctl", "reset-failed", "sssd.service"], capture_output=True)
        done += restore_sockets(before.get("sockets"))
    os.remove(record)
    return done
