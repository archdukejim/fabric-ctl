import json
import os
import subprocess
import sys

from fabriclib.common.errors import ValidationError


def _reminders(config_dir):
    """Purpose: the host's reminders, worked out here (outside fabric-agent's sandbox, which hides the homes).
    Inputs:  config_dir — the install's config folder.
    Returns: list of {"kind", "text"}: "break-glass" while the break-glass password's file is on the host;
             "local-account" for each local administrator account neither managed nor approved (2.1.6.78);
             "local-admin" while its rotation waits for OpenBao or its hourly check failed (2.1.7.20).
    Fails:   OSError from the record or the audit log.
    Feeds:   host_reminders (through the transient unit), this file's __main__."""
    from fabriclib.breakglass.break_glass_reminder import break_glass_reminder
    out = []
    glass = break_glass_reminder(config_dir)
    if glass:
        out.append({"kind": "break-glass", "text": glass["text"]})
    from fabriclib.hostaccounts.local_account_reminders import local_account_reminders
    out += [{"kind": r["kind"], "text": r["text"]} for r in local_account_reminders(config_dir)]
    from fabriclib.localadmin.local_admin_checks import local_admin_checks
    return out + [{"kind": "local-admin", "text": t} for t in local_admin_checks(None, config_dir, False)["warnings"]]


def host_reminders(deploy_base="/opt", run=subprocess.run):
    """Purpose: what the console reminds every administrator of, at each sign-in and on Overview (2.1.6.69): while the
             break-glass password's file is on the host, to copy it into safekeeping and delete it; each local
             administrator account OpenBao does not manage, until it is removed or approved (2.1.6.78). Worked out in a
             transient systemd unit, as root outside fabric-agent's sandbox (ProtectHome hides the file from the
             agent), as `fabricctl doctor`'s report is (doctor_report).
    Inputs:  deploy_base — the install root (default /opt); run — subprocess.run (tests give their own).
    Returns: list of {"kind", "text"}; [] when there is nothing to remind.
    Fails:   ValidationError "the reminders could not be read: …" when systemd-run fails or its output is not a list.
    Feeds:   agent route GET /v1/reminders (status:read) -> the console's top bar and Overview."""
    lib = os.path.join(deploy_base, "fabric", "lib")
    res = run(["systemd-run", "--wait", "--pipe", "--collect", "--quiet", f"--setenv=PYTHONPATH={lib}",
               sys.executable, "-m", "fabriclib.system.host_reminders", os.path.join(deploy_base, "fabric", "config")],
              capture_output=True, text=True, timeout=60)
    try:
        out = json.loads(res.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise ValidationError(f"the reminders could not be read: {(res.stderr or res.stdout).strip()[-300:]}")
    if not isinstance(out, list):
        raise ValidationError("the reminders could not be read: not a list")
    return out


if __name__ == "__main__":                    # the transient unit: the reminders as one JSON line
    print(json.dumps(_reminders(sys.argv[1] if len(sys.argv) > 1 else "/opt/fabric/config")))
