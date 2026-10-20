import json
import subprocess

from fabriclib.breakglass.break_glass_password import break_glass_password
from fabriclib.breakglass.constants import PASSWORD_LENGTH
from fabriclib.breakglass.write_break_glass_file import write_break_glass_file
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit


def reset_break_glass(v, config_dir, actor, container="samba", owner=None, audit=write_audit):
    """Purpose: a lost break-glass password replaced (manual 1.6.13.6; 2.1.6.75): a new generated one (as setup's,
             at least its tier's minimum length) set on `fabric-admin` inside this host's writable DC as the system
             (src/containers/samba/reset_break_glass.py; the password on stdin only), the account unlocked, the
             password written once to `~/fabric-admin/` of the person running sudo (write_break_glass_file, why
             "reset"), and audited `BREAK_GLASS_RESET` (never the password).
    Inputs:  v — rendered vars: ad_dc_type, ad_domain, ad_join_server, ad_tier_password_policies; config_dir — the
             install's config folder (the record); actor — who ran it (str); container — the DC's container (tests
             name their own); owner — (login, home, uid, gid) for the file, default sudo_owner(); audit — the audit
             writer (tests give their own).
    Returns: {"path": the file's path, "changed": [str], "disabled": bool (fabric-admin is disabled: reported, never
             changed)}.
    Fails:   ValidationError, before anything changes, on a host whose DC is read-only (naming the writable DC to run
             it on) or with no domain; ValidationError with the DC's message (the DC not running, no fabric-admin, the
             policy refusing the password); OSError when the file cannot be written (the password then set but
             unwritten: run it again); subprocess.TimeoutExpired after 120 s.
    Feeds:   breakglass/run_admin_command."""
    if not v.get("ad_domain"):
        raise ValidationError("this host has no domain: there is no fabric-admin to reset")
    if v.get("ad_dc_type") == "rodc":
        other = str(v.get("ad_join_server") or "").strip() or "a writable domain controller's host"
        raise ValidationError("this site's domain controller is read-only and takes no writes: run it on the host of "
                              f"{other} (2.1.6.75)")
    policy = (v.get("ad_tier_password_policies") or {}).get("enterprise_admin") or {}
    password = break_glass_password(max(PASSWORD_LENGTH, int(policy.get("minimum_length") or 0)))
    res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                          "/fabric/reset_break_glass.py"], input=json.dumps({"password": password}),
                         capture_output=True, text=True, timeout=120)
    if res.returncode != 0:
        raise ValidationError("fabric-admin's password could not be reset: "
                              + ((res.stderr or res.stdout).strip().splitlines() or ["the DC is not running"])[-1])
    out = json.loads(res.stdout)
    path = write_break_glass_file(password, v["ad_domain"], config_dir, why="reset", owner=owner)
    unlocked = any("unlocked" in c for c in out["changed"])
    audit(actor, "BREAK_GLASS_RESET", f"file={path} unlocked={'yes' if unlocked else 'no'}", "cli")
    return {"path": path, "changed": out["changed"], "disabled": out["disabled"]}
