from site_roles import CLASSES, FABRIC_ADMINS, fabric_admins, remote_users

HOSTS_OU = "fabric-hosts"            # the site's fabric host (1.6.11.11): a policy of its own by default (2.1.6.53)


def _host_default(site):
    """Purpose: the log-on policy of the site's OU=fabric-hosts while the setting names none (decision 2.1.6.53,
             manual 1.6.11.11): the fabric admins, at the keyboard and remotely, so the appliance is never open to the
             site's other people, whatever OU=machines or the site's OU allow. Mirrored by
             fabriclib/samba/logon_overview (what status shows).
    Inputs:  site — str.
    Returns: {"console": [names], "remote": [names]}.
    Fails:   never.
    Feeds:   plan_logon_entries."""
    groups = [FABRIC_ADMINS, fabric_admins(site)]
    return {"console": groups, "remote": list(groups)}


def plan_logon_entries(site, policies, legacy):
    """Purpose: the per-OU log-on GPOs fabric writes for a site (manual 1.6.11.4, 1.6.11.9.13; decision 2.1.7.14 as
             revised 2026-10-13): the setting's OUs, OU=fabric-hosts's default (2.1.6.53), and remote access by
             machine **class**: each class OU (`machines/servers`, `machines/desktops`) gets a GPO of its own unless
             the setting names that OU, granting remotely what the nearest policy above it grants (the setting's
             `machines`, else the site's, else the legacy groups) plus the class's `<site>-<class>-remote-users`, and at
             the keyboard what that policy grants (nothing written when no policy above names it). Every policy at or
             below a class OU names that class's group remotely too; no policy above the class OUs does, so a class
             group never reaches the other class. User rights are not merged between GPOs (the nearest one that sets
             a right wins), which is why the class GPO repeats what it inherits.
    Inputs:  site — str; policies — None (the legacy single GPO, 2.1.6.44) or {ou path: {"console": [names],
             "remote": [names]}}; legacy — the legacy groups' names (legacy_logon_groups), used when policies is None.
    Returns: {ou path: {"console": [names] or None (the right not written), "remote": [names]}}, the names in a
             stable order without repeats.
    Fails:   never.
    Feeds:   ensure_logon_policies; tests (pure)."""
    out = {ou: {"console": list(e.get("console") or []), "remote": list(e.get("remote") or [])}
           for ou, e in (policies or {}).items()}
    out.setdefault(HOSTS_OU, _host_default(site))
    for cls, ou in CLASSES.items():
        path, group = f"machines/{ou}", remote_users(site, cls)
        if path not in out:
            if policies is None:
                above = {"console": list(legacy), "remote": list(legacy)}
            else:
                above = out.get("machines", out.get(""))
            out[path] = {"console": list(above["console"] or []) if above else None,
                         "remote": list((above or {}).get("remote") or [])}
        for p, entry in out.items():
            if (p == path or p.startswith(path + "/")) and group not in entry["remote"]:
                entry["remote"].append(group)
    return out
