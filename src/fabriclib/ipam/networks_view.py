from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.fabric_options import fabric_options
from fabriclib.ipam.plan_rows import plan_rows
from fabriclib.ipam.subnet_map import subnet_map
from fabriclib.ipam.subnet_options import subnet_options
from fabriclib.ipam.suggestions import suggest_block


def networks_view(v, read, site, sites, leases=None):
    """Purpose: what the console's Networks tab shows of one site (manual 1.10.4.9, 1.10.4.21): its number, each
             VLAN with each of its subnets drawn as a map (subnet_map: the ranges as a bar, the counts, the address
             table with every address accounted for) and the options each subnet ends up with and where they came
             from (subnet_options), each reservation's own options, and the site's other networks. Pure: the reads
             are networks_overview's.
    Inputs:  v — fabric vars (what fabric_options reads; the settings' global dhcp.options); read — read_plan's
             result holding this site's plan; site — str; sites — the sites this console shows ([{"name", "own"}]);
             leases — this site's live leases (list_leases' rows) or None (another site's, or DHCP off).
             Option levels another part of fabric keeps are taken from the plan as they appear: read["options"]
             (the organisation's), the site's plan "options", a VLAN's "options".
    Returns: {"site", "block", "suggested_block", "sites" (each with "block" and "suggested"), "vlans": [{"id",
             "name", "purpose", "access", "notes", "subnets": [{plan fields, "bar", "counts", "rows", "options",
             "reservation_options": {ip: rows}}]}], "networks", "leases_shown" (bool)}.
    Fails:   never for a plan fabric wrote.
    Feeds:   networks_overview; the dev preview."""
    plan = site_plan(read, site)
    raw = (read.get("plans") or {}).get(site) or {}
    rows = plan_rows(plan, leases)
    mine = any(s["name"] == site and s.get("own") for s in sites)  # this install's: fabric's options apply
    blocks = {s["name"]: s.get("block") for s in read.get("sites") or []}
    out = {"site": site, "block": plan["block"], "suggested_block": suggest_block(read.get("sites") or [], site),
           "sites": [{**s, "block": blocks.get(s["name"]),
                      "suggested": suggest_block(read.get("sites") or [], s["name"])} for s in sites],
           "vlans": [], "networks": plan["networks"], "leases_shown": leases is not None}
    for vlan in plan["vlans"]:
        entry = {**vlan, "subnets": []}
        for sub in [s for s in plan["subnets"] if s.get("vlan") == vlan["id"]]:
            drawn = subnet_map(sub, [r for r in rows if r["subnet"] == sub["cidr"]])
            levels = {"fabric": fabric_options(v, sub.get("gateway") or "") if mine else [],
                      "organisation": read.get("options") or [], "site": raw.get("options") or [],
                      "settings": (v.get("dhcp") or {}).get("options") or [] if mine else [],
                      "vlan": vlan.get("options") or [], "subnet": sub.get("options") or []}
            reserved = {a["ip"]: subnet_options({**levels, "reservation": a["options"]})
                        for a in sub.get("addresses") or [] if a.get("options")}
            entry["subnets"].append({**{k: x for k, x in sub.items() if k not in ("addresses",)}, **drawn,
                                     "options": subnet_options(levels), "reservation_options": reserved})
        out["vlans"].append(entry)
    return out
