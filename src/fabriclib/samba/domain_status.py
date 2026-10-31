import os
import subprocess

from fabriclib.common.paths import INSTALL_DIR
from fabriclib.localadmin.record import load_record
from fabriclib.samba.summarize_roles import summarize_roles


def _dc(args):
    """Purpose: run one samba-tool query inside the running DC.
    Inputs:  args — list of str after `samba-tool`.
    Returns: list of str, its output's non-empty lines; [] when the DC is not running or the query fails.
    Fails:   never (FileNotFoundError without docker is reported as no lines).
    Feeds:   domain_status."""
    try:
        res = subprocess.run(["docker", "exec", "samba", "samba-tool", *args, "-s", "/data/etc/smb.conf"],
                             capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in res.stdout.splitlines() if line.strip()] if res.returncode == 0 else []


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
    roles = _dc(["fsmo", "show"])
    return {"domain": v.get("ad_domain"), "realm": v.get("ad_realm"), "netbios": v.get("ad_netbios"),
            "dc": v.get("hostname_dc"), "running": state == "healthy", "roles": roles,
            "role_summary": summarize_roles(roles, v.get("hostname_dc")),
            "policy": _dc(["domain", "passwordsettings", "show"])[1:],
            "local_admin_ssh": _ssh_on(config_dir or os.path.join(INSTALL_DIR, "config"))}
