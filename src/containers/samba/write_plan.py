import json

import ldb

import paths

# what each kind of plan entry holds: the field fabric names it by -> its attribute (manual 1.10.4.13, 1.10.4.33)
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
# an option set (the domain's, or a site's on its record, 2.1.10.34): its lists and their attributes
SET_FIELDS = {"options": "fabricDhcpOption", "option_defs": "fabricDhcpOptionDef", "client_classes": "fabricDhcpClass"}
WHATS = ("vlan", "subnet", "range", "address", "block", "options")


def values_of(value):
    """Purpose: a field's value as the attribute's values: booleans as TRUE/FALSE, a list of objects as one JSON
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


def _exists(samdb, dn):
    """Purpose: whether an entry is there.
    Inputs:  samdb — SamDB; dn — str or ldb.Dn.
    Returns: bool.
    Fails:   ldb.LdbError other than "no such object".
    Feeds:   write_plan."""
    try:
        samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["cn"])
        return True
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        return False


def _record(samdb, site):
    """Purpose: a site's record, which must be there for its number or its options to be written (convergence makes
             it, 1.10.4.32).
    Inputs:  samdb — SamDB; site — str.
    Returns: ldb.Dn.
    Fails:   ValueError "no such site: <site>".
    Feeds:   write_plan."""
    dn = paths.site_record_dn(samdb, site)
    if not _exists(samdb, dn):
        raise ValueError(f"no such site: {site}")
    return dn


def _write_set(samdb, change):
    """Purpose: one option set's lists replaced (manual 1.10.4.24.1, 1.10.4.32): the domain's entry, or a site's
             record; neither is made here (convergence makes both).
    Inputs:  samdb — SamDB (as the DC's agent); change — {"key" ("domain" or a site), "fields" ({options,
             option_defs, client_classes}: each given list replaces the attribute's values)}.
    Returns: str, what changed.
    Fails:   ValueError: the domain's entry not there yet, or no such site; ldb.LdbError when AD refuses.
    Feeds:   write_plan."""
    key = change.get("key")
    if key == "domain":
        dn, label = paths.domain_options_dn(samdb), "the domain's DHCP options"
        if not _exists(samdb, dn):
            raise ValueError("the domain's DHCP options are not in the domain yet: run an apply at the root site")
    else:
        dn, label = _record(samdb, key), f"{key}'s DHCP options"
    msg = ldb.Message(ldb.Dn(samdb, str(dn)))
    for k, v in (change.get("fields") or {}).items():
        if k in SET_FIELDS:
            msg[SET_FIELDS[k]] = ldb.MessageElement(values_of(v), ldb.FLAG_MOD_REPLACE, SET_FIELDS[k])
    if len(msg) > 0:
        samdb.modify(msg)
    return f"{label} changed"


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
        from read_plan import listed, split_netboot
        found = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["fabricDhcpOption"])[0]
        have_opts, have_boot = split_netboot(listed(found.get("fabricDhcpOption")))
    options = list(fields.get("options") or []) if "options" in fields else have_opts
    netboot = fields.pop("netboot") if "netboot" in fields else have_boot
    fields["options"] = options + ([{"netboot": netboot}] if netboot else [])


def entry_dn(samdb, change):
    """Purpose: where one entry of the plan lives (manual 1.10.4.33): a VLAN `CN=<site>/vlan/<id>` and a subnet
             `CN=<site>/<name>` in the domain's OU=networks, a range or an address below its subnet's entry.
    Inputs:  samdb — SamDB; change — {"what", "site", "key" (a VLAN's ID, a subnet's name, a range's
             "<kind>-<first>", an address), "subnet" (a range's or an address's)}.
    Returns: ldb.Dn (every name escaped, whatever it holds).
    Fails:   ValueError for a change with no site, or a range or address with no subnet.
    Feeds:   write_plan."""
    site, what, key = str(change.get("site") or ""), change["what"], str(change.get("key", ""))
    if not site:
        raise ValueError(f"a {what} change names no site")
    if what == "vlan":
        return paths.plan_entry_dn(samdb, site, f"vlan/{key}")
    if what == "subnet":
        return paths.plan_entry_dn(samdb, site, key)
    if not change.get("subnet"):
        raise ValueError(f"a {what} change names no subnet")
    return paths.plan_entry_dn(samdb, site, str(change["subnet"]), below=key)


def write_plan(samdb, lp, site, changes):
    """Purpose: write changes to the address plan (manual 1.10.4.13, 1.10.4.32, 1.10.4.33), in order: VLANs, subnets (a
             fabricNetwork entry given the fabricSubnet class, also one convergence wrote before the upgrade), ranges,
             addresses, a site's number on its record and the option sets. fabric-agent checks every rule and the
             grants (1.10.4.34) before it asks; AD lets the DC's agent write OU=networks and CN=fabric,CN=System.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: each change names its
             site); changes — list of {"do" ("add", "set" or "remove"), "what" (one of WHATS), "site", "key" (an
             entry's name; for "options" "domain" or a site's name), "subnet" (for a range or an address), "fields"
             ({field: value}; a set field of "" or None is removed; a subnet's or address's "netboot" goes into
             fabricDhcpOption with its options, 2.1.10.25; "block": {"block"}; "options": "options", "option_defs",
             "client_classes", each replacing its list, 2.1.10.23)}.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a change AD refuses (the changes before it stay made); ValueError for a change of an
             unknown kind, no such site, no site or subnet named.
    Feeds:   directory_ops (op "write_plan")."""
    done = []
    for c in changes:
        what, do = c.get("what"), c.get("do")
        if what not in WHATS or do not in ("add", "set", "remove"):
            raise ValueError(f"unknown plan change: {do} {what}")
        if what == "options":
            done.append(_write_set(samdb, c))
            continue
        if what == "block":
            msg = ldb.Message(_record(samdb, c.get("site")))
            number = (c.get("fields") or {}).get("block")
            msg["fabricBlock"] = ldb.MessageElement(values_of(number), ldb.FLAG_MOD_REPLACE, "fabricBlock")
            samdb.modify(msg)
            done.append(f"block of {c['site']} set to {number}")
            continue
        dn = entry_dn(samdb, c)
        label = f"{what} {c.get('key', '')} of {c['site']}".replace("  ", " ")
        if do == "remove":
            samdb.delete(dn, ["tree_delete:1"])
            done.append(f"{label} removed")
            continue
        given = dict(c.get("fields") or {})
        if what in ("subnet", "address"):
            _with_netboot(samdb, dn if do == "set" else None, given)
        fields = {FIELDS[what][k]: values_of(v) for k, v in given.items() if k in FIELDS[what]}
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
        for attr, vals in fields.items():
            msg[attr] = ldb.MessageElement(vals, ldb.FLAG_MOD_REPLACE, attr)
        if len(msg) > 0:
            samdb.modify(msg)
        done.append(f"{label} changed")
    return done
