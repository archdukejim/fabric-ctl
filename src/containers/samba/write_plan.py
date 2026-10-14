import json

import ldb

from paths import organisation_dn, site_dn

# what each kind of plan entry holds: the field fabric names it by -> its attribute (manual 1.10.4.13)
FIELDS = {
    "vlan": {"id": "fabricVlan", "name": "fabricVlanName", "purpose": "fabricPurpose", "access": "fabricAccess",
             "notes": "description"},
    "subnet": {"cidr": "fabricCidr", "vlan": "fabricVlan", "kind": "fabricNetworkKind", "gateway": "fabricGateway",
               "dhcp": "fabricDhcpServed", "id": "fabricSubnetId", "relay": "fabricRelay", "notes": "description",
               "allow_overlap": "fabricAllowOverlap", "options": "fabricDhcpOption"},
    "range": {"kind": "fabricRangeKind", "first": "fabricFirst", "last": "fabricLast", "notes": "description"},
    "address": {"ip": "fabricIp", "kind": "fabricAddressKind", "name": "fabricHostName", "mac": "fabricMac",
                "owner": "fabricOwner", "notes": "description", "dns": "fabricDns", "options": "fabricDhcpOption",
                # a reservation's device role (MAB from a reservation, 1.11.1.7): AD's auxiliary fabricDeviceRoles
                "role": "fabricRoleName"},
}
CLASSES = {"vlan": ["fabricVlanRecord"], "subnet": ["fabricNetwork", "fabricSubnet"], "range": ["fabricRange"],
           "address": ["fabricAddress"]}
# an option set (the organisation's or a site's, 2.1.10.23): its lists and their attributes
SET_FIELDS = {"options": "fabricDhcpOption", "option_defs": "fabricDhcpOptionDef", "client_classes": "fabricDhcpClass"}


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


def _set_dn(samdb, key):
    """Purpose: where an option set lives: the organisation's in OU=organisation, a site's in the site's own OU.
    Inputs:  samdb — SamDB; key — "org" or a site's name.
    Returns: str, the entry's DN.
    Fails:   ValueError "no such site: <key>"; LookupError without an organisation OU.
    Feeds:   _write_set."""
    if key == "org":
        return f"CN=dhcp-options,{organisation_dn(samdb)}"
    try:
        return f"CN=dhcp-options,{site_dn(samdb, key)}"
    except LookupError:
        raise ValueError(f"no such site: {key}")


def _write_set(samdb, change):
    """Purpose: one option set's lists replaced (manual 1.10.4.24.1): a site's entry is made by its first write; the
             organisation's is made by the top site's convergence (only its editors may write it, not create it).
    Inputs:  samdb — SamDB (as the site's agent); change — {"key" ("org" or a site), "fields" ({options,
             option_defs, client_classes}: each given list replaces the attribute's values)}.
    Returns: str, what changed.
    Fails:   ValueError: the organisation's entry not there yet, or no such site; ldb.LdbError when AD refuses (a site
             the top has not added to fabric-dhcp-org-editors: insufficient access).
    Feeds:   write_plan."""
    dn = _set_dn(samdb, change["key"])
    fields = {SET_FIELDS[k]: _values(v) for k, v in (change.get("fields") or {}).items() if k in SET_FIELDS}
    found = samdb.search(base=dn.split(",", 1)[1], scope=ldb.SCOPE_ONELEVEL,
                         expression="(&(objectClass=fabricOptionSet)(cn=dhcp-options))", attrs=["cn"])
    label = "the organisation's DHCP options" if change["key"] == "org" else f"{change['key']}'s DHCP options"
    if not found:
        if change["key"] == "org":
            raise ValueError("the organisation's DHCP options are not in the domain yet: run an apply at the top site")
        samdb.add({"dn": dn, "objectClass": "fabricOptionSet", **{a: v for a, v in fields.items() if v}})
        return f"{label} added"
    msg = ldb.Message(ldb.Dn(samdb, dn))
    for attr, values in fields.items():
        msg[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)
    if len(msg) > 0:
        samdb.modify(msg)
    return f"{label} changed"


def _write_local_scan(samdb, change):
    """Purpose: whether a site's own admins may start scans, written on the site's OU by a site above (decision
             2.1.10.30, manual 1.10.4.29.4): the OU given the auxiliary class fabricLocalScanSet when it lacks it, then
             fabricLocalScan and who set it. AD denies the site's own agent and OU admins (ensure_site_acl).
    Inputs:  samdb — SamDB (as the site's agent); change — {"site", "fields": {"allowed" (bool, or None to clear
             both attributes), "by" (text)}}.
    Returns: str, what changed.
    Fails:   ValueError "no such site"; ldb.LdbError when AD refuses (the site itself, a sibling, a site below).
    Feeds:   write_plan."""
    try:
        dn = site_dn(samdb, change["site"])
    except LookupError:
        raise ValueError(f"no such site: {change['site']}")
    given = change.get("fields") or {}
    have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["objectClass"])[0]
    if "fabricLocalScanSet" not in [str(c) for c in have["objectClass"]]:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "objectClass": "fabricLocalScanSet"}, ldb.FLAG_MOD_ADD))
    msg = ldb.Message(ldb.Dn(samdb, dn))
    cleared = given.get("allowed") is None          # clear: both removed, the branch back to the default (off)
    msg["fabricLocalScan"] = ldb.MessageElement([] if cleared else _values(bool(given.get("allowed"))),
                                                ldb.FLAG_MOD_REPLACE, "fabricLocalScan")
    msg["fabricLocalScanBy"] = ldb.MessageElement(_values(str(given.get("by") or "")), ldb.FLAG_MOD_REPLACE,
                                                  "fabricLocalScanBy")
    samdb.modify(msg)
    if cleared:
        return f"local scans at {change['site']} cleared (off by default)"
    return f"local scans at {change['site']} {'allowed' if given.get('allowed') else 'off'}"


def _with_netboot(samdb, dn, fields):
    """Purpose: a subnet's or an address's options and netboot preset written together into fabricDhcpOption (the
             preset is one named value, {"netboot": {...}}, 2.1.10.25): the one the change does not give is kept from
             the entry.
    Inputs:  samdb — SamDB; dn — the entry (None for one being added); fields — the change's fields, changed in place
             ("netboot" folded into "options").
    Returns: None.
    Fails:   ldb.LdbError reading the entry.
    Feeds:   write_plan."""
    if "options" not in fields and "netboot" not in fields:
        return
    have_opts, have_boot = [], None
    if dn is not None and ("options" not in fields or "netboot" not in fields):
        for value in samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["fabricDhcpOption"])[0].get(
                "fabricDhcpOption") or []:
            pos, _, text = str(value).partition(":")
            try:
                o = (int(pos), json.loads(text))
            except ValueError:
                continue
            if isinstance(o[1], dict) and set(o[1]) == {"netboot"}:
                have_boot = o[1]["netboot"]
            else:
                have_opts.append(o)
        have_opts = [o for _, o in sorted(have_opts, key=lambda x: x[0])]
    options = list(fields.get("options") or []) if "options" in fields else have_opts
    netboot = fields.pop("netboot") if "netboot" in fields else have_boot
    fields["options"] = options + ([{"netboot": netboot}] if netboot else [])


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
             write which site (1.6.3.6: a site's agent, its own site and the sites below it); the organisation's
             option set, its editors' group (2.1.10.23).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str (unused: each change names its
             site); changes — list of {"do" ("add", "set" or "remove"), "what" ("vlan", "subnet", "range",
             "address", "block", "options" or "local_scan"), "site", "key" (the entry's name: a VLAN's ID, a
             subnet's name, a range's "<kind>-<first>", an address; for "options" "org" or a site's name), "subnet"
             (for a range or an address), "fields" ({field: value}; a set field of "" or None is removed; a subnet's
             or address's "netboot" goes into fabricDhcpOption with its options, 2.1.10.25; an option set's
             "options", "option_defs", "client_classes" each replace their list, 2.1.10.23; "local_scan" (the site
             below): "allowed" and "by", 2.1.10.30)}.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a change AD refuses (the changes before it stay made); ValueError for a site with no
             OU or a change of an unknown kind.
    Feeds:   directory_ops (op "write_plan")."""
    done = []
    for c in changes:
        what, do = c.get("what"), c.get("do")
        if what not in ("vlan", "subnet", "range", "address", "block", "options", "local_scan") or do not in (
                "add", "set", "remove"):
            raise ValueError(f"unknown plan change: {do} {what}")
        if what == "options":
            done.append(_write_set(samdb, c))
            continue
        if what == "local_scan":
            done.append(_write_local_scan(samdb, c))
            continue
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
        given = dict(c.get("fields") or {})
        if what in ("subnet", "address") and do != "remove":
            _with_netboot(samdb, dn if do == "set" else None, given)
        fields = {FIELDS[what][k]: _values(v) for k, v in given.items() if k in FIELDS[what]}
        if do == "remove":
            samdb.delete(dn, ["tree_delete:1"])
            done.append(f"{label} removed")
            continue
        if do == "add":
            classes = CLASSES[what] + (["fabricDeviceRoles"] if fields.get("fabricRoleName") else [])
            msg = {"dn": dn, "objectClass": classes, **{a: v for a, v in fields.items() if v}}
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
        if what == "address" and fields.get("fabricRoleName"):    # a role named: the auxiliary class first
            have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["objectClass"])[0]
            if "fabricDeviceRoles" not in [str(x) for x in have["objectClass"]]:
                samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(dn), "objectClass": "fabricDeviceRoles"},
                                                   ldb.FLAG_MOD_ADD))
        msg = ldb.Message(dn)
        for attr, values in fields.items():
            msg[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)
        if len(msg) > 0:
            samdb.modify(msg)
        done.append(f"{label} changed")
    return done
