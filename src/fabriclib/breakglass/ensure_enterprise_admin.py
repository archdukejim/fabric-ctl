import json
import subprocess

from fabriclib.breakglass.break_glass_password import break_glass_password
from fabriclib.breakglass.constants import PASSWORD_LENGTH
from fabriclib.common.errors import ValidationError


def ensure_enterprise_admin(v, container="samba", password=None):
    """Purpose: `fabric-admin`, the Enterprise Admin (manual 1.6.12.2; 2.1.6.68, 2.1.6.69), made once at the root's DC,
             inside it as the system (src/containers/samba/ensure_enterprise_admin.py): in OU=people, in Enterprise,
             Schema and Domain Admins, not in directory-admins, with a generated password (break_glass_password) that
             goes to the DC on stdin only. An existing account is left with its password.
    Inputs:  v — rendered vars: dc_name, ldap_groups (the users gid), posix_home_base, posix_login_shell,
             ad_tier_password_policies (written with it; the password as long as its policy's minimum, 24 at
             least); container — the DC's container (tests name their own); password — the password to give it (default:
             a new generated one; tests give their own).
    Returns: {"created": bool, "changed": [str], "password": the password when created, else None}. The caller writes
             it to the one file (write_break_glass_file) and nowhere else.
    Fails:   ValidationError with the DC's message (the DC not running, AD refusing); subprocess.TimeoutExpired after
             120 s.
    Feeds:   setup/create_admin (at the root)."""
    policies = v.get("ad_tier_password_policies") or {}
    length = max(PASSWORD_LENGTH, int((policies.get("enterprise_admin") or {}).get("minimum_length") or 0))
    password = password or break_glass_password(length)
    users_gid = next((int(g["gidNumber"]) for g in v.get("ldap_groups") or [] if g["name"] == "users"), 5000)
    request = {"password": password, "dc": v["dc_name"], "gid": users_gid,
               "home_base": v.get("posix_home_base") or "/home", "shell": v.get("posix_login_shell") or "/bin/bash",
               "policies": policies or None}
    res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                          "/fabric/ensure_enterprise_admin.py"], input=json.dumps(request), capture_output=True,
                         text=True, timeout=120)
    if res.returncode != 0:
        raise ValidationError("fabric-admin, the Enterprise Admin, could not be made: "
                              + ((res.stderr or res.stdout).strip().splitlines() or ["the DC is not running"])[-1])
    out = json.loads(res.stdout)
    return {"created": out["created"], "changed": out["changed"], "password": password if out["created"] else None}
