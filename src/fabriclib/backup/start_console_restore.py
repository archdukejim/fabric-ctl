import os
import subprocess

from fabriclib.backup.console_restore_running import LOG, UNIT, console_restore_running
from fabriclib.common.errors import ValidationError

KEY_FILE = "/run/fabric/console-restore.key"
FABRICCTL = "/usr/bin/fabricctl"


def start_console_restore(path, key, actor, run=subprocess.run, key_file=KEY_FILE, log=LOG):
    """Purpose: the console's whole restore started (manual 1.3.7.9): `fabricctl reinstall --from <bundle>` as the
             systemd unit fabric-console-restore, which outlives fabric-agent and the console it stops. The key goes in
             a root-only file in /run (RAM) that the command reads once and removes; never on a command line. Its
             output is appended to the log in the backups folder.
    Inputs:  path — the bundle (checked by the caller: check_whole_restore); key — {"passphrase"} or {"private_key"};
             actor — the person (FABRIC_ACTOR, for the audit); run, key_file, log — subprocess.run and the paths
             (tests).
    Returns: {"unit", "log"}.
    Fails:   ValidationError when one already runs, or systemd-run refuses (the key file removed again).
    Feeds:   agent/post_backup (reinstall)."""
    if console_restore_running(run):
        raise ValidationError("a whole restore from the console is running already: follow it in "
                              f"{log} on the host")
    os.makedirs(os.path.dirname(key_file), mode=0o700, exist_ok=True)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write((key.get("private_key") or key.get("passphrase") or "") + "\n")
    res = run(["systemd-run", f"--unit={UNIT}", "--collect", "--property=Type=exec", "--property=UMask=0077",
               f"--property=StandardOutput=append:{log}", f"--property=StandardError=append:{log}",
               f"--setenv=FABRIC_ACTOR={actor}", "--setenv=NO_COLOR=1",
               FABRICCTL, "reinstall", "--from", path, "--key-file-once", key_file, "--yes", "--non-interactive"],
              capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        if os.path.exists(key_file):
            os.remove(key_file)
        raise ValidationError(f"the restore could not start: {(res.stderr or res.stdout).strip()[-300:]}")
    return {"unit": UNIT, "log": log}
