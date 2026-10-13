# the site's fabric host's OU (manual 1.6.11.11): a log-on policy of its own even when the setting names none
HOSTS_OU = "fabric-hosts"


def host_logon_default(site):
    """Purpose: the log-on policy of the site's OU=fabric-hosts while `logon_policies` names none (decision 2.1.6.53,
             manual 1.6.11.11): the fabric admins, at the keyboard and remotely, so the appliance is never open to the
             site's other people. The DC writes the same (src/containers/samba/ensure_logon_policies, _host_default).
    Inputs:  site — str, the site's name.
    Returns: {"console": [group names], "remote": [group names]}.
    Fails:   never.
    Feeds:   samba/logon_overview (what is shown), samba/set_logon_policy (a right left out keeps the default's)."""
    groups = ["fabric-admins", f"{site}-fabric-admins"]
    return {"console": groups, "remote": list(groups)}
