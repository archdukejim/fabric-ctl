import subprocess

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


def domain_status(v):
    """Purpose: what `fabricctl domain status` shows (manual 4.6.5): the domain, this DC and whether it runs, the
             domain-wide roles it holds, the password policy in force.
    Inputs:  v — rendered vars: ad_domain, ad_realm, ad_netbios, hostname_dc.
    Returns: dict {"domain", "realm", "netbios", "dc", "running" (bool), "roles" [str], "role_summary"
             (summarize_roles: the roles named plainly), "policy" [str]}.
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
            "policy": _dc(["domain", "passwordsettings", "show"])[1:]}
