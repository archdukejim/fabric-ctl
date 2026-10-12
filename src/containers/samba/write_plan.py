import json

import ldb

from paths import site_dn

# what each kind of plan entry holds: the field fabric names it by -> its attribute (manual 1.10.4.13)
FIELDS = {
    "vlan": {"id": "fabricVlan", "name": "fabricVlanName", "purpose": "fabricPurpose", "access": "fabricAccess",
             "notes": "description"},
    "subnet": {"cidr": "fabricCidr", "vlan": "fabricVlan", "kind": "fabricNetworkKind", "gateway": "fabricGateway",
               "dhcp": "fabricDhcpServed", "id": "fabricSubnetId", "relay": "fabricRelay", "notes": "description",
               "allow_overlap": "fabricAllowOverlap", "options": "fabricDhcpOption"},
    "range": {"kind": "fabricRangeKind", "first": "fabricFirst", "last": "fabricLast", "notes": "description"},
    "address": {"ip": "fabricIp", "kind": "fabricAddressKind", "name": "fabricHostName", "mac": "fabricMac",
                "owner": "fabricOwner", "notes": "description", "dns": "fabricDns", "options": "fabricDhcpOption"},
}
CLASSES = {"vlan": ["fabricVlanRecord"], "subnet": ["fabricNetwork", "fabricSubnet"], "range": ["fabricRange"],
           "address": ["fabricAddress"]}


def _values(value):
    """Purpose: a field's value as the attribute's values: booleans as TRUE/FALSE, a list of options as one JSON
             object per value prefixed with its position (LDAP keeps no order), nothing for "" or None.
    Inputs:  value — str, int, bool, list of dicts, or None.
    Returns: list of str.
    Fails:   never.
    Feeds:   write_plan."""
    if value is None or value == "" or value == []:
        return []
    if isinstance(value, bool):
        return ["TRUE" if value else "FALSE"]
    if isinstance(value, list):
        return [f"{i}:{json.dumps(o, sort_keys=True)}" for i, o in enumerate(value)]
    return [str(value)]


def _dn(samdb, change):
    """Purpose: where one entry of the plan lives: a VLAN or a subnet in its site's OU=networks, a range or an address
             below its subnet's entry, the block on the site's OU.
    Inputs:  samdb — SamDB; change — {"what", "site", "key", "subnet" (a range's or address's subnet)}.
    Returns: ldb.Dn (every name escaped, whatever it holds).
    Fails:   ValueError "no such site: <site>".
    Feeds:   write_plan."""
    try:
        site = site_dn(samdb, change["site"])
    except LookupError:
        raise ValueError(f"no such site: {change['site']}")
    if change["what"] == "block":
        return ldb.Dn(samdb, site)
    base = f"OU=networks,{site}"
    if change["what"] in ("range", "address"):
        parent = ldb.Dn(samdb, f"CN=x,{base}")
        parent.set_component(0, "CN", change["subnet"])
        base = str(parent)
    dn = ldb.Dn(samdb, f"CN=x,{base}")
    dn.set_component(0, "CN", str(change["key"]))
    return dn


def write_plan(samdb, lp, site, changes):
    """Purpose: write changes to the address plan (manual 1.10.4.13), in order: VLANs, subnets (a fabricNetwork entry
             given the fabricSubnet class, also one convergence wrote before the upgrade), ranges, addresses and a
             site's block. fabric checks every rule before it asks (fabriclib/ipam); AD's access rules decide who may
             write which site (1.6.3.6: a site's agent, its own site and the sites below it).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str (unused: each change names its
             site); changes — list of {"do" ("add", "set" or "remove"), "what" ("vlan", "subnet", "range",
             "address" or "block"), "site", "key" (the entry's name: a VLAN's ID, a subnet's name, a range's
             "<kind>-<first>", an address), "subnet" (for a range or an address), "fields" ({field: value}; a set
             field of "" or None is removed)}.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a change AD refuses (the changes before it stay made); ValueError for a site with no
             OU or a change of an unknown kind.
    Feeds:   directory_ops (op "write_plan")."""
    done = []
    for c in changes:
        what, do = c.get("what"), c.get("do")
        if what not in ("vlan", "subnet", "range", "address", "block") or do not in ("add", "set", "remove"):
            raise ValueError(f"unknown plan change: {do} {what}")
        dn = _dn(samdb, c)
        label = f"{what} {c.get('key', '')} of {c['site']}".replace("  ", " ")
        if what == "block":
            have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["objectClass"])[0]
            if "fabricAddressBlock" not in [str(x) for x in have["objectClass"]]:
                samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(dn), "objectClass": "fabricAddressBlock"},
                                                   ldb.FLAG_MOD_ADD))
            msg = ldb.Message(dn)
            msg["fabricBlock"] = ldb.MessageElement(_values(c["fields"].get("block")), ldb.FLAG_MOD_REPLACE,
                                                    "fabricBlock")
            samdb.modify(msg)
            done.append(f"block of {c['site']} set to {c['fields'].get('block')}")
            continue
        fields = {FIELDS[what][k]: _values(v) for k, v in (c.get("fields") or {}).items() if k in FIELDS[what]}
        if do == "remove":
            samdb.delete(dn, ["tree_delete:1"])
            done.append(f"{label} removed")
            continue
        if do == "add":
            msg = {"dn": dn, "objectClass": CLASSES[what], **{a: v for a, v in fields.items() if v}}
            if what in ("vlan", "subnet"):
                msg["fabricSite"] = c["site"]
            samdb.add(msg)
            done.append(f"{label} added")
            continue
        if what == "subnet":                  # an entry convergence wrote before the upgrade: the class first
            have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["objectClass"])[0]
            if "fabricSubnet" not in [str(x) for x in have["objectClass"]]:
                samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(dn), "objectClass": "fabricSubnet"},
                                                   ldb.FLAG_MOD_ADD))
        msg = ldb.Message(dn)
        for attr, values in fields.items():
            msg[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)
        if len(msg) > 0:
            samdb.modify(msg)
        done.append(f"{label} changed")
    return done
