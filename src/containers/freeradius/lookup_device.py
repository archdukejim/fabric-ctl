import ldap.filter

from directory import folder_dn, load_config, search


def _vals(attrs, key):
    """Purpose: an LDAP attribute's values as str.
    Inputs:  attrs — dict {attr: [bytes]} from a search; key — str attribute name (exact case).
    Returns: list of UTF-8 decoded str; [] when absent.
    Fails:   UnicodeDecodeError for a value that is not UTF-8.
    Feeds:   lookup_device."""
    return [v.decode() for v in attrs.get(key) or []]


def lookup_device(attribute, value, permission):
    """Purpose: find the device whose `attribute` is `value` in the domain's OU=devices and judge it for `permission`:
             access is the union of its roles' permissions, nothing while it is disabled; the VLAN comes from the role
             with the lowest priority number that sets one (ties by name) — the same rules as the web UI
             (list_devices).
    Inputs:  attribute — "fabricCertFingerprint" or "macAddress"; value — str (escaped into the filter);
             permission — "network:eap-tls" or "network:mab". Reads OU=devices, and the roles each device names
             (fabricRoleName) from OU=device-roles (manual 1.6.13.2: the domain's, 2.1.6.80).
    Returns: dict {device, allowed, vlan, reason}; device is None if no device, or more than one, has the value.
             A device without fabricEnabled counts as enabled.
    Fails:   ldap errors from search; ValueError if a role's fabricVlan or fabricPriority is not a number;
             load_config errors. The caller turns any of these into Access-Reject.
    Feeds:   fabric_radius._decide."""
    conf = load_config()
    devices = search(folder_dn(conf, "devices"),
                     "(&(objectClass=device)(%s=%s))" % (attribute, ldap.filter.escape_filter_chars(value)),
                     ["cn", "fabricEnabled", "fabricRoleName"])
    if len(devices) != 1:
        return {"device": None, "allowed": False, "vlan": None,
                "reason": "no device has it" if not devices else "more than one device has it"}
    dn, attrs = devices[0]
    name = (_vals(attrs, "cn") or ["?"])[0]
    if (_vals(attrs, "fabricEnabled") or ["TRUE"])[0].upper() != "TRUE":
        return {"device": name, "allowed": False, "vlan": None, "reason": "device disabled"}
    roles = []
    names = _vals(attrs, "fabricRoleName")
    wanted = "(|%s)" % "".join("(cn=%s)" % ldap.filter.escape_filter_chars(n) for n in names) if names else None
    for _, a in (search(folder_dn(conf, "device-roles"), "(&(objectClass=fabricRole)%s)" % wanted,
                        ["cn", "fabricPermission", "fabricVlan", "fabricPriority"], subtree=True)
                 if wanted else []):
        roles.append({"name": (_vals(a, "cn") or [""])[0], "permissions": _vals(a, "fabricPermission"),
                      "vlan": int((_vals(a, "fabricVlan") or ["0"])[0]) or None,
                      "priority": int((_vals(a, "fabricPriority") or ["100"])[0])})
    if not any(permission in r["permissions"] for r in roles):
        return {"device": name, "allowed": False, "vlan": None, "reason": f"no role grants {permission}"}
    vlan_role = next((r for r in sorted(roles, key=lambda r: (r["priority"], r["name"])) if r["vlan"]), None)
    return {"device": name, "allowed": True, "vlan": vlan_role["vlan"] if vlan_role else None, "reason": ""}
