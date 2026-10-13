from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.options.effective_options import effective_options
from fabriclib.ipam.options.settings_options import settings_options
from fabriclib.ipam.plan_rows import plan_rows
from fabriclib.ipam.subnet_map import subnet_map
from fabriclib.ipam.suggestions import suggest_block


def networks_view(v, read, site, sites, leases=None):
    """Purpose: what the console's Networks tab shows of one site (manual 1.10.4.9, 1.10.4.21): its number, each
             VLAN with each of its subnets drawn as a map (subnet_map: the ranges as a bar, the counts, the address
             table with every address accounted for) and the options each subnet's clients end up with and where
             each came from (effective_options, the one provenance function: 2.3.10.5.7), each reservation's own
             options, and the site's other networks. A VLAN has no options of its own: its view shows its subnets'.
             Pure: the reads are networks_overview's.
    Inputs:  v — fabric vars (fabric's own option values and the settings' options not moved yet, for this
             install's site only); read — read_plan's result holding this site's plan and the option sets; site —
             str; sites — the sites this console shows ([{"name", "own"}]); leases — this site's live leases
             (list_leases' rows) or None (another site's, or DHCP off).
    Returns: {"site", "block", "suggested_block", "sites" (each with "block" and "suggested"), "vlans": [{"id",
             "name", "purpose", "access", "notes", "subnets": [{plan fields, "bar", "counts", "rows", "options"
             (effective_options' rows), "classes" (its classes that may apply), "reservation_options": {ip: the
             reservation's own rows}}]}], "networks", "leases_shown" (bool)}.
    Fails:   never for a plan fabric wrote.
    Feeds:   networks_overview; the dev preview."""
    plan = site_plan(read, site)
    rows = plan_rows(plan, leases)
    mine = any(s["name"] == site and s.get("own") for s in sites)  # this install's: its own values and settings
    here = v if mine else None
    settings = settings_options(v) if mine else None
    blocks = {s["name"]: s.get("block") for s in read.get("sites") or []}
    out = {"site": site, "block": plan["block"], "suggested_block": suggest_block(read.get("sites") or [], site),
           "sites": [{**s, "block": blocks.get(s["name"]),
                      "suggested": suggest_block(read.get("sites") or [], s["name"])} for s in sites],
           "vlans": [], "networks": plan["networks"], "leases_shown": leases is not None}
    for vlan in plan["vlans"]:
        entry = {**vlan, "subnets": []}
        for sub in [s for s in plan["subnets"] if s.get("vlan") == vlan["id"]]:
            drawn = subnet_map(sub, [r for r in rows if r["subnet"] == sub["cidr"]])
            eff = effective_options(plan, "subnet", sub["name"], here, settings)
            reserved = {a["ip"]: [r for r in effective_options(plan, "address", a["ip"], here, settings)["rows"]
                                  if r["source"].startswith("address")]
                        for a in sub.get("addresses") or [] if a.get("options")}
            entry["subnets"].append({**{k: x for k, x in sub.items() if k not in ("addresses",)}, **drawn,
                                     "options": eff["rows"], "classes": eff["classes"],
                                     "reservation_options": reserved})
        out["vlans"].append(entry)
    return out
