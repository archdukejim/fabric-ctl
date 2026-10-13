import json

import ldb

from paths import site_dn, sites_dn

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


def _options(m):
    """Purpose: the DHCP options an entry carries (fabricDhcpOption: one JSON object per value, as fabric wrote it).
    Inputs:  m — ldb.Message.
    Returns: list of dicts, in the order they were written (each value starts with its position, "<n>:").
    Fails:   never: a value that is not JSON is skipped (fabric writes them all).
    Feeds:   read_plan."""
    out = []
    for value in m.get("fabricDhcpOption") or []:
        pos, _, text = str(value).partition(":")
        try:
            out.append((int(pos), json.loads(text)))
        except ValueError:
            continue
    return [o for _, o in sorted(out, key=lambda x: x[0])]


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
             "dns" (bool), "options", "role" (a reservation's device role, "" for none: 1.11.1.7)}]}],
             "networks": [{"name", "cidr", "kind", "vlan", "notes",
             "allow_overlap"}]}}}: lists sorted; a site without entries has no key in plans unless it is `of`.
    Fails:   ldb.LdbError from the searches; ValueError "no such site: <of>".
    Feeds:   directory_ops (op "read_plan")."""
    sites = []
    for m in samdb.search(base=sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, expression="(objectClass=fabricSiteInfo)",
                          attrs=["ou", "whenCreated", "fabricBlock"]):
        sites.append({"name": _one(m, "ou"), "created": _one(m, "whenCreated"),
                      "block": int(_one(m, "fabricBlock")) if _one(m, "fabricBlock") else None})
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
                          "allow_overlap": _one(m, "fabricAllowOverlap"), "options": _options(m)})
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
                                        "dns": _one(m, "fabricDns").upper() == "TRUE", "options": _options(m),
                                        "role": _one(m, "fabricRoleName")})
    for plan in plans.values():
        plan["vlans"].sort(key=lambda x: x["id"])
        plan["subnets"].sort(key=lambda x: (x["vlan"] or 0, x["name"]))
        plan["networks"].sort(key=lambda x: x["name"])
        for s in plan["subnets"]:
            s["ranges"].sort(key=lambda r: tuple(int(p) for p in r["first"].split(".")))
            s["addresses"].sort(key=lambda a: tuple(int(p) for p in a["ip"].split(".")))
    return {"sites": sorted(sites, key=lambda x: (x["created"], x["name"])), "plans": plans}
