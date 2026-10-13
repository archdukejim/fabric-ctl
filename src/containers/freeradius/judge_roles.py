import ldap.filter

from directory import load_config, search, site_dn


def judge_roles(names, permission):
    """Purpose: judge the device roles an entry names (a device's, or a reservation's, fabricRoleName) for
             `permission`: access is the union of the roles' permissions; the VLAN comes from the role with the lowest
             priority number that sets one (ties by name), the same rules as the web UI (list_devices). Only this
             site's own roles (OU=device-roles of the site) and the organisation's count (manual 1.6.3.4).
    Inputs:  names — list of str role names; permission — "network:eap-tls" or "network:mab".
    Returns: dict {allowed (bool), vlan (int or None), reason ("" when allowed)}.
    Fails:   ldap errors from search; ValueError if a role's fabricVlan or fabricPriority is not a number;
             load_config errors. Callers turn any of these into Access-Reject.
    Feeds:   lookup_device, lookup_reservation."""
    if not names:
        return {"allowed": False, "vlan": None, "reason": f"no role grants {permission}"}
    conf = load_config()
    own = (",OU=device-roles," + site_dn(conf)).lower()
    wanted = "(|%s)" % "".join("(cn=%s)" % ldap.filter.escape_filter_chars(n) for n in names)
    roles = []
    for role_dn, a in search("OU=sites," + conf["base"], "(&(objectClass=fabricRole)%s)" % wanted,
                             ["cn", "fabricPermission", "fabricVlan", "fabricPriority"], subtree=True):
        if not role_dn.lower().endswith(own) and ",ou=device-roles,ou=organisation," not in role_dn.lower():
            continue                     # another site's own role of the same name is not this site's
        roles.append({"name": [v.decode() for v in a.get("cn") or [b""]][0],
                      "permissions": [v.decode() for v in a.get("fabricPermission") or []],
                      "vlan": int(([v.decode() for v in a.get("fabricVlan") or []] or ["0"])[0]) or None,
                      "priority": int(([v.decode() for v in a.get("fabricPriority") or []] or ["100"])[0])})
    if not any(permission in r["permissions"] for r in roles):
        return {"allowed": False, "vlan": None, "reason": f"no role grants {permission}"}
    vlan_role = next((r for r in sorted(roles, key=lambda r: (r["priority"], r["name"])) if r["vlan"]), None)
    return {"allowed": True, "vlan": vlan_role["vlan"] if vlan_role else None, "reason": ""}
