import json

import ldb

from paths import organisation_dn, site_dn, sites_dn

KINDS = ("(|(objectClass=fabricVlanRecord)(objectClass=fabricNetwork)(objectClass=fabricRange)"
         "(objectClass=fabricAddress))")
ATTRS = ["objectClass", "cn", "fabricSite", "fabricCidr", "fabricVlan", "fabricVlanName", "fabricNetworkKind",
         "fabricAllowOverlap", "description", "fabricPurpose", "fabricAccess", "fabricGateway", "fabricDhcpServed",
         "fabricSubnetId", "fabricRelay", "fabricDhcpOption", "fabricRangeKind", "fabricFirst", "fabricLast",
         "fabricIp", "fabricAddressKind", "fabricMac", "fabricHostName", "fabricOwner", "fabricDns", "fabricRoleName"]


def _site_of(dn):
    """Purpose: the site an entry of the plan belongs to: the OU right after its OU=networks (sites nest, 2.1.6.20).
    Inputs:  dn — str, an entry's DN.
    Returns: str, the site's name; "" for an entry outside any OU=networks.
    Fails:   never.
    Feeds:   read_plan."""
    parts = [p.split("=", 1) for p in str(dn).split(",")]
    for i, (key, value) in enumerate(parts[:-1]):
        if key.upper() == "OU" and value.lower() == "networks":
            return parts[i + 1][1]
    return ""


def _one(m, name):
    """Purpose: one attribute of a search result as text.
    Inputs:  m — ldb.Message; name — attribute.
    Returns: str ("" when absent).
    Fails:   never.
    Feeds:   read_plan."""
    return str(m.get(name, idx=0) or "")


def _listed(m, attr="fabricDhcpOption"):
    """Purpose: the JSON objects an entry carries in a positional attribute (fabricDhcpOption, fabricDhcpOptionDef,
             fabricDhcpClass: one object per value, as fabric wrote it, each value starting with its position "<n>:").
    Inputs:  m — ldb.Message; attr — the attribute.
    Returns: list of dicts, in the order they were written.
    Fails:   never: a value that is not JSON is skipped (fabric writes them all).
    Feeds:   _options, _option_set."""
    out = []
    for value in m.get(attr) or []:
        pos, _, text = str(value).partition(":")
        try:
            out.append((int(pos), json.loads(text)))
        except ValueError:
            continue
    return [o for _, o in sorted(out, key=lambda x: x[0])]


def _options(m):
    """Purpose: the DHCP options an entry carries, and its netboot preset: kept as a named option, one value of
             fabricDhcpOption holding {"netboot": {...}} (2.1.10.25), read apart from the options.
    Inputs:  m — ldb.Message.
    Returns: (list of option dicts, the preset dict or None).
    Fails:   never.
    Feeds:   read_plan."""
    options, netboot = [], None
    for o in _listed(m):
        if isinstance(o, dict) and set(o) == {"netboot"}:
            netboot = o["netboot"]
        else:
            options.append(o)
    return options, netboot


def _option_set(m):
    """Purpose: one option set (the organisation's or a site's, 2.1.10.23) as fabric reads it.
    Inputs:  m — ldb.Message of a fabricOptionSet entry.
    Returns: {"options", "option_defs", "client_classes"} (lists).
    Fails:   never.
    Feeds:   read_plan."""
    return {"options": _listed(m), "option_defs": _listed(m, "fabricDhcpOptionDef"),
            "client_classes": _listed(m, "fabricDhcpClass")}


def _option_sets(samdb, of):
    """Purpose: the organisation's option set and each site's (or `of`'s alone), and the sites the top lets edit the
             organisation's (their agent in fabric-dhcp-org-editors, manual 1.10.4.24.2).
    Inputs:  samdb — SamDB; of — a site's name, or "" for every site.
    Returns: ({"org": set or None, <site>: set, ...}, sorted list of site names).
    Fails:   ldb.LdbError from the searches.
    Feeds:   read_plan."""
    try:
        org = organisation_dn(samdb).lower()
    except LookupError:                   # no organisation yet (a domain being made)
        org = ""
    sets = {"org": None}
    for m in samdb.search(base=sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, expression="(objectClass=fabricOptionSet)",
                          attrs=["fabricDhcpOption", "fabricDhcpOptionDef", "fabricDhcpClass"]):
        parent = str(m.dn.parent())
        if parent.lower() == org:
            sets["org"] = _option_set(m)
            continue
        owner = parent.split(",", 1)[0].split("=", 1)[1]
        if not of or owner == of:
            sets[owner] = _option_set(m)
    if of:
        sets.setdefault(of, {"options": [], "option_defs": [], "client_classes": []})
    editors = []
    for g in samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                          expression="(&(objectClass=group)(sAMAccountName=fabric-dhcp-org-editors))",
                          attrs=["member"]):
        for member in g.get("member") or []:
            cn = str(member).split(",", 1)[0].split("=", 1)[1]
            if cn.startswith("fabric-agent-"):
                editors.append(cn[len("fabric-agent-"):])
    return sets, sorted(editors)


def _local_scan(m, top_dn):
    """Purpose: whether a site's own admins may start scans there (decision 2.1.10.30, manual 1.10.4.29.4): set from
             above on its OU, off when unset; the top site has no site above it and always may. With the sites above
             it, nearest first, read from its OU's place (sites nest, 2.1.6.20): who may change a value set from higher
             up is decided by them (2.1.10.30's revision: the highest ancestor that set it wins).
    Inputs:  m — ldb.Message of a site's OU (fabricLocalScan, fabricLocalScanBy); top_dn — "OU=sites,<domain>",
             lower case.
    Returns: {"allowed" (bool: the setting, TRUE only), "set_by" (text, "" unset), "top" (bool: right below
             OU=sites), "above" (list of site names, nearest first; [] at the top)}.
    Fails:   never.
    Feeds:   read_plan."""
    above, dn = [], str(m.dn).split(",", 1)[1]
    while dn.lower() != top_dn and dn.upper().startswith("OU="):
        above.append(dn.split(",", 1)[0].split("=", 1)[1])
        dn = dn.split(",", 1)[1]
    return {"allowed": _one(m, "fabricLocalScan").upper() == "TRUE", "set_by": _one(m, "fabricLocalScanBy"),
            "top": not above, "above": above}


def read_plan(samdb, lp, site, of=""):
    """Purpose: the address plan of the address manager (manual 1.10.4.4, 1.10.4.13): each site's VLANs, subnets with
             their ranges and addresses, and its other networks (the LAN convergence writes), plus every site's
             number (block) and when its OU was made (the suggested block is a site's order in the organisation).
    Inputs:  samdb — SamDB (as the site's agent: AD's read access applies); lp — LoadParm (unused); site — str
             (unused: any site's plan may be read); of — a site's name, or "" for every site.
    Returns: {"sites": [{"name", "created" (whenCreated text), "block" (int or None)}], "plans": {site: {"vlans":
             [{"id", "name", "purpose", "access", "notes"}], "subnets": [{"name", "cidr", "vlan", "kind", "gateway",
             "dhcp" (bool), "id" (Kea's subnet id or None), "relay", "notes", "allow_overlap", "options", "ranges":
             [{"kind", "first", "last", "notes"}], "addresses": [{"ip", "kind", "name", "mac", "owner", "notes",
             "dns" (bool), "options", "netboot", "role" (a reservation's device role, "" for none:
             1.11.1.7)}]}], "networks": [{"name", "cidr", "kind", "vlan", "notes",
             "allow_overlap"}]}}, "option_sets": {"org": {"options", "option_defs", "client_classes"} or None,
             <site>: the same}, "org_editors": [site names] (2.1.10.23), "options" (the organisation's options; and
             each plan's "options", the site's: the shape the Networks tab reads, 2.3.10.5.7), "local_scan" ({site:
             _local_scan's}, every site's, 2.1.10.30)}: lists sorted; a site
             without entries has no key in plans unless it is `of`; a subnet's and an address's "netboot" is its
             preset or None (2.1.10.25).
    Fails:   ldb.LdbError from the searches; ValueError "no such site: <of>".
    Feeds:   directory_ops (op "read_plan")."""
    sites, local = [], {}
    top_dn = sites_dn(samdb).lower()
    for m in samdb.search(base=sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, expression="(objectClass=fabricSiteInfo)",
                          attrs=["ou", "whenCreated", "fabricBlock", "fabricLocalScan", "fabricLocalScanBy"]):
        sites.append({"name": _one(m, "ou"), "created": _one(m, "whenCreated"),
                      "block": int(_one(m, "fabricBlock")) if _one(m, "fabricBlock") else None})
        local[_one(m, "ou")] = _local_scan(m, top_dn)
    try:
        base = f"OU=networks,{site_dn(samdb, of)}" if of else sites_dn(samdb)
    except LookupError:
        raise ValueError(f"no such site: {of}")
    plans = {of: {"vlans": [], "subnets": [], "networks": []}} if of else {}
    found = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression=KINDS, attrs=ATTRS)
    subnets = {}
    for m in found:
        owner = _site_of(m.dn)
        if not owner or (of and owner != of):
            continue
        plan = plans.setdefault(owner, {"vlans": [], "subnets": [], "networks": []})
        classes = {str(c) for c in m["objectClass"]}
        if "fabricVlanRecord" in classes:
            plan["vlans"].append({"id": int(_one(m, "fabricVlan")), "name": _one(m, "fabricVlanName"),
                                  "purpose": _one(m, "fabricPurpose"), "access": _one(m, "fabricAccess") or "full",
                                  "notes": _one(m, "description")})
        elif "fabricSubnet" in classes:
            entry = subnets.setdefault(str(m.dn).lower(), {"ranges": [], "addresses": []})
            entry.update({"name": _one(m, "cn"), "cidr": _one(m, "fabricCidr"),
                          "vlan": int(_one(m, "fabricVlan")) if _one(m, "fabricVlan") else None,
                          "kind": _one(m, "fabricNetworkKind"), "gateway": _one(m, "fabricGateway"),
                          "dhcp": _one(m, "fabricDhcpServed").upper() == "TRUE",
                          "id": int(_one(m, "fabricSubnetId")) if _one(m, "fabricSubnetId") else None,
                          "relay": _one(m, "fabricRelay"), "notes": _one(m, "description"),
                          "allow_overlap": _one(m, "fabricAllowOverlap"), "options": _options(m)[0],
                          "netboot": _options(m)[1]})
            plan["subnets"].append(entry)
        elif "fabricNetwork" in classes:
            plan["networks"].append({"name": _one(m, "cn"), "cidr": _one(m, "fabricCidr"),
                                     "kind": _one(m, "fabricNetworkKind"),
                                     "vlan": int(_one(m, "fabricVlan")) if _one(m, "fabricVlan") else None,
                                     "notes": _one(m, "description"), "allow_overlap": _one(m, "fabricAllowOverlap")})
    for m in found:                       # ranges and addresses, each below its subnet's entry
        classes = {str(c) for c in m["objectClass"]}
        if not classes & {"fabricRange", "fabricAddress"}:
            continue
        parent = subnets.get(str(m.dn.parent()).lower())
        if parent is None:
            continue
        if "fabricRange" in classes:
            parent["ranges"].append({"kind": _one(m, "fabricRangeKind"), "first": _one(m, "fabricFirst"),
                                     "last": _one(m, "fabricLast"), "notes": _one(m, "description")})
        else:
            parent["addresses"].append({"ip": _one(m, "fabricIp"), "kind": _one(m, "fabricAddressKind"),
                                        "name": _one(m, "fabricHostName"), "mac": _one(m, "fabricMac"),
                                        "owner": _one(m, "fabricOwner"), "notes": _one(m, "description"),
                                        "dns": _one(m, "fabricDns").upper() == "TRUE", "options": _options(m)[0],
                                        "netboot": _options(m)[1], "role": _one(m, "fabricRoleName")})
    for plan in plans.values():
        plan["vlans"].sort(key=lambda x: x["id"])
        plan["subnets"].sort(key=lambda x: (x["vlan"] or 0, x["name"]))
        plan["networks"].sort(key=lambda x: x["name"])
        for s in plan["subnets"]:
            s["ranges"].sort(key=lambda r: tuple(int(p) for p in r["first"].split(".")))
            s["addresses"].sort(key=lambda a: tuple(int(p) for p in a["ip"].split(".")))
    option_sets, editors = _option_sets(samdb, of)
    for name, plan in plans.items():      # the Networks tab's shape (1.10.4.21.4): a site's options in its plan
        plan["options"] = (option_sets.get(name) or {}).get("options") or []
    return {"sites": sorted(sites, key=lambda x: (x["created"], x["name"])), "plans": plans,
            "options": (option_sets.get("org") or {}).get("options") or [],
            "option_sets": option_sets, "org_editors": editors, "local_scan": local}
