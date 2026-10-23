import json

import ldb

import paths

KINDS = ("(|(objectClass=fabricVlanRecord)(objectClass=fabricNetwork)(objectClass=fabricRange)"
         "(objectClass=fabricAddress))")
ATTRS = ["objectClass", "cn", "fabricSite", "fabricCidr", "fabricVlan", "fabricVlanName", "fabricNetworkKind",
         "fabricAllowOverlap", "description", "fabricPurpose", "fabricAccess", "fabricGateway", "fabricDhcpServed",
         "fabricSubnetId", "fabricRelay", "fabricDhcpOption", "fabricRangeKind", "fabricFirst", "fabricLast",
         "fabricIp", "fabricAddressKind", "fabricMac", "fabricHostName", "fabricOwner", "fabricDns"]
SET_ATTRS = ["cn", "whenCreated", "fabricBlock", "fabricDhcpOption", "fabricDhcpOptionDef", "fabricDhcpClass"]


def _one(m, name):
    """Purpose: one attribute of a search result as text.
    Inputs:  m — ldb.Message; name — attribute.
    Returns: str ("" when absent).
    Fails:   never.
    Feeds:   read_plan."""
    return str(m.get(name, idx=0) or "")


def listed(values):
    """Purpose: the JSON objects a positional attribute holds (fabricDhcpOption, fabricDhcpOptionDef, fabricDhcpClass:
             one object per value, each value starting with its position "<n>:", as write_plan writes them; LDAP keeps
             no order).
    Inputs:  values — the attribute's values (anything str() gives "<n>:<JSON>"), or None.
    Returns: list of the objects, in their positions' order; a value that is not "<n>:<JSON>" is skipped.
    Fails:   never.
    Feeds:   read_plan."""
    out = []
    for value in values or []:
        pos, _, text = str(value).partition(":")
        try:
            out.append((int(pos), json.loads(text)))
        except ValueError:
            continue
    return [o for _, o in sorted(out, key=lambda x: x[0])]


def split_netboot(objects):
    """Purpose: a subnet's or an address's options and its netboot preset, kept together in fabricDhcpOption as one
             value {"netboot": {...}} beside the options (2.1.10.25).
    Inputs:  objects — listed()'s list.
    Returns: (list of option dicts, the preset dict or None).
    Fails:   never.
    Feeds:   read_plan."""
    options, netboot = [], None
    for o in objects:
        if isinstance(o, dict) and set(o) == {"netboot"}:
            netboot = o["netboot"]
        else:
            options.append(o)
    return options, netboot


def _option_set(m):
    """Purpose: one option set (the domain's, or a site's on its record: 2.1.10.34) as fabric reads it.
    Inputs:  m — ldb.Message with the three option attributes.
    Returns: {"options", "option_defs", "client_classes"} (lists).
    Fails:   never.
    Feeds:   read_plan."""
    return {"options": listed(m.get("fabricDhcpOption")), "option_defs": listed(m.get("fabricDhcpOptionDef")),
            "client_classes": listed(m.get("fabricDhcpClass"))}


def _sort_ip(text):
    """Purpose: a sort key for a dotted IPv4 address (a bad one sorts first).
    Inputs:  text — str.
    Returns: tuple of int.
    Fails:   never.
    Feeds:   read_plan."""
    try:
        return tuple(int(p) for p in text.split("."))
    except ValueError:
        return ()


def read_plan(samdb, lp, site, of=""):
    """Purpose: the address plan (manual 1.10.4.4, 1.10.4.32, 1.10.4.33): every site's record (its number, when it was
             made, its option set), the domain's option set, and each site's VLANs and subnets (the domain's
             OU=networks entries whose fabricSite names it) with the ranges and addresses below each subnet, and its
             other networks (the LAN convergence writes).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: any site's plan may be
             read); of — a site's name, or "" for every site.
    Returns: {"sites": [{"name", "created" (whenCreated text), "block" (int or None)}] by when made then name,
             "plans": {site: {"vlans": [{"id", "name", "purpose", "access", "notes"}], "subnets": [{"name", "cidr",
             "vlan", "kind", "gateway", "dhcp" (bool), "id" (Kea's subnet id or None), "relay", "notes",
             "allow_overlap", "options", "netboot", "ranges": [{"kind", "first", "last", "notes"}], "addresses":
             [{"ip", "kind", "name", "mac", "owner", "notes", "dns" (bool), "options", "netboot"}]}], "networks":
             [{"name", "cidr", "kind", "vlan", "notes", "allow_overlap"}], "options" (the site's)}}, "option_sets":
             {"domain": set or None, <site>: {"options", "option_defs", "client_classes"}}, "options" (the domain's
             options)}; every list sorted; a site without entries has a plan only when it is `of`.
    Fails:   ValueError "no such site: <of>" (no record of it); ldb.LdbError from the searches (but a missing
             CN=sites or domain set: none yet).
    Feeds:   directory_ops (op "read_plan")."""
    sites, sets = [], {"domain": None}
    try:
        records = samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_ONELEVEL,
                               expression="(objectClass=fabricSiteRecord)", attrs=SET_ATTRS)
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        records = []
    for m in records:
        name = _one(m, "cn")
        sites.append({"name": name, "created": _one(m, "whenCreated"),
                      "block": int(_one(m, "fabricBlock")) if _one(m, "fabricBlock") else None})
        if not of or name == of:
            sets[name] = _option_set(m)
    if of and of not in {s["name"] for s in sites}:
        raise ValueError(f"no such site: {of}")
    try:
        found = samdb.search(base=paths.domain_options_dn(samdb), scope=ldb.SCOPE_BASE, attrs=SET_ATTRS)
        sets["domain"] = _option_set(found[0])
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
    plans = {of: {"vlans": [], "subnets": [], "networks": []}} if of else {}
    found = samdb.search(base=paths.folder_dn(samdb, "networks"), scope=ldb.SCOPE_SUBTREE, expression=KINDS,
                         attrs=ATTRS)
    subnets = {}
    for m in found:
        classes = {str(c) for c in m["objectClass"]}
        if classes & {"fabricRange", "fabricAddress"}:
            continue
        owner = _one(m, "fabricSite")
        if not owner or (of and owner != of):
            continue
        plan = plans.setdefault(owner, {"vlans": [], "subnets": [], "networks": []})
        vlan = int(_one(m, "fabricVlan")) if _one(m, "fabricVlan") else None
        if "fabricVlanRecord" in classes:
            plan["vlans"].append({"id": vlan, "name": _one(m, "fabricVlanName"), "purpose": _one(m, "fabricPurpose"),
                                  "access": _one(m, "fabricAccess") or "full", "notes": _one(m, "description")})
        elif "fabricSubnet" in classes:
            options, netboot = split_netboot(listed(m.get("fabricDhcpOption")))
            entry = subnets.setdefault(str(m.dn).lower(), {"ranges": [], "addresses": []})
            entry.update({"name": _one(m, "cn").split("/", 1)[-1], "cidr": _one(m, "fabricCidr"), "vlan": vlan,
                          "kind": _one(m, "fabricNetworkKind"), "gateway": _one(m, "fabricGateway"),
                          "dhcp": _one(m, "fabricDhcpServed").upper() == "TRUE",
                          "id": int(_one(m, "fabricSubnetId")) if _one(m, "fabricSubnetId") else None,
                          "relay": _one(m, "fabricRelay"), "notes": _one(m, "description"),
                          "allow_overlap": _one(m, "fabricAllowOverlap"), "options": options, "netboot": netboot})
            plan["subnets"].append(entry)
        else:
            plan["networks"].append({"name": _one(m, "cn").split("/", 1)[-1], "cidr": _one(m, "fabricCidr"),
                                     "kind": _one(m, "fabricNetworkKind"), "vlan": vlan,
                                     "notes": _one(m, "description"), "allow_overlap": _one(m, "fabricAllowOverlap")})
    for m in found:                       # ranges and addresses, each below its subnet's entry
        classes = {str(c) for c in m["objectClass"]}
        parent = subnets.get(str(m.dn.parent()).lower()) if classes & {"fabricRange", "fabricAddress"} else None
        if parent is None:
            continue
        if "fabricRange" in classes:
            parent["ranges"].append({"kind": _one(m, "fabricRangeKind"), "first": _one(m, "fabricFirst"),
                                     "last": _one(m, "fabricLast"), "notes": _one(m, "description")})
        else:
            options, netboot = split_netboot(listed(m.get("fabricDhcpOption")))
            parent["addresses"].append({"ip": _one(m, "fabricIp"), "kind": _one(m, "fabricAddressKind"),
                                        "name": _one(m, "fabricHostName"), "mac": _one(m, "fabricMac"),
                                        "owner": _one(m, "fabricOwner"), "notes": _one(m, "description"),
                                        "dns": _one(m, "fabricDns").upper() == "TRUE", "options": options,
                                        "netboot": netboot})
    for name, plan in plans.items():
        plan["vlans"].sort(key=lambda x: x["id"] or 0)
        plan["subnets"].sort(key=lambda x: (x["vlan"] or 0, x["name"]))
        plan["networks"].sort(key=lambda x: x["name"])
        for s in plan["subnets"]:
            s["ranges"].sort(key=lambda r: _sort_ip(r["first"]))
            s["addresses"].sort(key=lambda a: _sort_ip(a["ip"]))
        plan["options"] = (sets.get(name) or {}).get("options") or []
    return {"sites": sorted(sites, key=lambda x: (x["created"], x["name"])), "plans": plans,
            "options": (sets.get("domain") or {}).get("options") or [], "option_sets": sets}
