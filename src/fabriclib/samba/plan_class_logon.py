from fabriclib.samba.host_logon_default import HOSTS_OU, host_logon_default

# a machine's class -> its OU below the site's OU=machines (2.1.6.36 as revised 2026-10-13); the DC's copy:
# src/containers/samba/site_roles.CLASSES (tests/samba/class_logon_test.py keeps the two in step)
CLASSES = {"server": "servers", "desktop": "desktops"}


def plan_class_logon(site, policies, legacy):
    """Purpose: the per-OU log-on policies the site's DC writes, as status shows them (manual 1.6.11.4,
             1.6.11.9.13; decision 2.1.7.14 as revised 2026-10-13): the setting's OUs, OU=fabric-hosts's default, and
             each class OU's (`machines/servers`, `machines/desktops`) granting remotely what the nearest policy
             above grants plus `<site>-<class>-remote-users`. The host's mirror of the DC's plan_logon_entries
             (src/containers/samba), which writes them.
    Inputs:  site — str; policies — None (the legacy single policy) or {ou path: {"console", "remote"}}; legacy — the
             legacy groups' names (used when policies is None).
    Returns: {ou path: {"console": [names] or None (inherited: not set there), "remote": [names]}}.
    Fails:   never.
    Feeds:   samba/logon_overview."""
    out = {ou: {"console": list(e.get("console") or []), "remote": list(e.get("remote") or [])}
           for ou, e in (policies or {}).items()}
    out.setdefault(HOSTS_OU, host_logon_default(site))
    for cls, ou in CLASSES.items():
        path, group = f"machines/{ou}", f"{site}-{cls}-remote-users"
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
