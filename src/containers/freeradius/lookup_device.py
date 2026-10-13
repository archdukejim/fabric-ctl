import ldap.filter

from directory import load_config, search, site_dn
from judge_roles import judge_roles


def _vals(attrs, key):
    """Purpose: an LDAP attribute's values as str.
    Inputs:  attrs — dict {attr: [bytes]} from a search; key — str attribute name (exact case).
    Returns: list of UTF-8 decoded str; [] when absent.
    Fails:   UnicodeDecodeError for a value that is not UTF-8.
    Feeds:   lookup_device."""
    return [v.decode() for v in attrs.get(key) or []]


def lookup_device(attribute, value, permission):
    """Purpose: find the device whose `attribute` is `value` in this site's OU=devices and judge it for `permission`:
             nothing while it is disabled, else its roles judged by judge_roles (the union of their permissions; the
             VLAN of the lowest priority number) — the same rules as the web UI (list_devices).
    Inputs:  attribute — "fabricCertFingerprint" or "macAddress"; value — str (escaped into the filter);
             permission — "network:eap-tls" or "network:mab". Reads the site's OU=devices, and the roles each device
             names (fabricRoleName) from the site's own OU=device-roles and the organisation's (manual 1.6.3.4).
    Returns: dict {device, allowed, vlan, reason}; device is None if no device, or more than one, has the value
             (reason "no device has it" or "more than one device has it"). A device without fabricEnabled counts as
             enabled.
    Fails:   ldap errors from search; ValueError if a role's fabricVlan or fabricPriority is not a number;
             load_config errors. The caller turns any of these into Access-Reject.
    Feeds:   fabric_radius._decide."""
    conf = load_config()
    site = site_dn(conf)
    devices = search("OU=devices," + site,
                     "(&(objectClass=device)(%s=%s))" % (attribute, ldap.filter.escape_filter_chars(value)),
                     ["cn", "fabricEnabled", "fabricRoleName"])
    if len(devices) != 1:
        return {"device": None, "allowed": False, "vlan": None,
                "reason": "no device has it" if not devices else "more than one device has it"}
    dn, attrs = devices[0]
    name = (_vals(attrs, "cn") or ["?"])[0]
    if (_vals(attrs, "fabricEnabled") or ["TRUE"])[0].upper() != "TRUE":
        return {"device": name, "allowed": False, "vlan": None, "reason": "device disabled"}
    return {"device": name, **judge_roles(_vals(attrs, "fabricRoleName"), permission)}
