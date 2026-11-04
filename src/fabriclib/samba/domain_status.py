import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import INSTALL_DIR
from fabriclib.directory.run_op import run_op
from fabriclib.localadmin.record import load_record
from fabriclib.samba.summarize_roles import summarize_roles
from fabriclib.secrets.load_secrets import load_secrets


def _facts(v):
    """Purpose: the DC's roles and password policy (the op roles_and_policy, in samba-tool's words).
    Inputs:  v — rendered vars.
    Returns: {"roles": [str], "policy": [str]}; both empty when the DC is not running or cannot be asked.
    Fails:   never.
    Feeds:   domain_status."""
    try:
        return run_op(v, load_secrets(), "roles_and_policy")
    except (ValidationError, OSError, ValueError, subprocess.TimeoutExpired):
        return {"roles": [], "policy": []}


def _ssh_on(config_dir):
    """Purpose: whether this host's local-admin is let in over SSH, as last applied (manual 1.7.1.4.6).
    Inputs:  config_dir — the install's config folder.
    Returns: bool.
    Fails:   never (an unreadable record: False).
    Feeds:   domain_status."""
    try:
        return (load_record(config_dir).get("ssh") or {}).get("on") is True
    except (OSError, ValueError):
        return False


def domain_status(v, config_dir=None):
    """Purpose: what `fabricctl domain status` shows (manual 4.6.5): the domain, this DC and whether it runs, the
             domain-wide roles it holds, the password policy in force.
    Inputs:  v — rendered vars: ad_domain, ad_realm, ad_netbios, hostname_dc; config_dir — the install's config
             folder (the local-admin record; default <INSTALL_DIR>/config).
    Returns: dict {"domain", "realm", "netbios", "dc", "running" (bool), "roles" [str], "role_summary"
             (summarize_roles: the roles named plainly), "policy" [str], "local_admin_ssh" (bool: this host's
             local-admin let in over SSH, a relaxation, 2.1.7.19)}.
    Fails:   never (a DC that does not answer shows as not running, with no roles or policy).
    Feeds:   run_domain_command (status); domain_overview (the console's Domain section)."""
    try:
        state = subprocess.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", "samba"],
                               capture_output=True, text=True, timeout=10).stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        state = ""
    facts = _facts(v)
    roles = facts["roles"]
    return {"domain": v.get("ad_domain"), "realm": v.get("ad_realm"), "netbios": v.get("ad_netbios"),
            "dc": v.get("hostname_dc"), "running": state == "healthy", "roles": roles,
            "role_summary": summarize_roles(roles, v.get("hostname_dc")),
            "policy": facts["policy"],
            "local_admin_ssh": _ssh_on(config_dir or os.path.join(INSTALL_DIR, "config"))}
