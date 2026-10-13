import ldap.dn
import ldap.filter

from directory import load_config, search, site_dn
from judge_roles import judge_roles


def _one(attrs, key):
    """Purpose: an LDAP attribute's first value as str.
    Inputs:  attrs — dict {attr: [bytes]}; key — attribute name.
    Returns: str ("" when absent).
    Fails:   UnicodeDecodeError for a value that is not UTF-8.
    Feeds:   lookup_reservation."""
    return ((attrs.get(key) or [b""])[0]).decode()


def lookup_reservation(mac):
    """Purpose: MAB from a DHCP reservation (manual 1.11.1.7): find the reservation of this site's address plan that
             holds `mac` (OU=networks, fabricAddressKind=reservation, fabricMac) and judge the device role it names for
             network:mab (judge_roles). The VLAN is the reservation's subnet's (the address only works there), else the
             role's.
    Inputs:  mac — str, normalized aa:bb:cc:dd:ee:ff (fabric writes fabricMac so, 1.10.4.3.2).
    Returns: dict {device (the reservation's name, else its address; None when no reservation, or more than one, has
             the MAC), allowed, vlan, reason}.
    Fails:   ldap errors from search; ValueError for a VLAN or priority that is not a number; load_config errors.
             The caller turns any of these into Access-Reject.
    Feeds:   fabric_radius._decide (a MAB request whose MAC no device has)."""
    conf = load_config()
    base = "OU=networks," + site_dn(conf)
    found = search(base, "(&(objectClass=fabricAddress)(fabricAddressKind=reservation)(fabricMac=%s))"
                   % ldap.filter.escape_filter_chars(mac), ["fabricIp", "fabricHostName", "fabricRoleName"],
                   subtree=True)
    if len(found) != 1:
        return {"device": None, "allowed": False, "vlan": None,
                "reason": "no device has it" if not found else "more than one reservation has it"}
    dn, attrs = found[0]
    name = _one(attrs, "fabricHostName") or _one(attrs, "fabricIp") or "?"
    roles = [v.decode() for v in attrs.get("fabricRoleName") or []]
    if not roles:
        return {"device": name, "allowed": False, "vlan": None, "reason": "reservation has no role"}
    judged = judge_roles(roles, "network:mab")
    if not judged["allowed"]:
        return {"device": name, **judged}
    subnet = ldap.dn.str2dn(dn)[1][0][1]          # the address's parent entry: its subnet
    subnets = search(base, "(&(objectClass=fabricNetwork)(cn=%s))" % ldap.filter.escape_filter_chars(subnet),
                     ["fabricVlan"])
    vlan = int(_one(subnets[0][1], "fabricVlan") or 0) if subnets else 0
    return {"device": name, "allowed": True, "vlan": vlan or judged["vlan"], "reason": ""}
