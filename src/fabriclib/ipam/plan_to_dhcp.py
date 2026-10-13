from fabriclib.ipam.options.merge_option_sets import merge_option_sets
from fabriclib.ipam.options.netboot_classes import netboot_classes


def plan_to_dhcp(plan):
    """Purpose: what Kea and fabric's DNS are rendered from, out of a site's plan (manual 1.10.4.5, 1.10.4.14): each
             subnet served by DHCP as the `dhcp.subnets` entry the Kea template and normalize_dhcp know (its id, name,
             VLAN, notes, access from its VLAN, gateway as router, relay, options, its dhcp ranges as pools and its
             reservations), and every address published in DNS (static, infrastructure or a reservation, 2.1.10.17)
             as an A record of the site's zone (its PTR follows, dns/reverse_zones). A reservation published so is
             `"ddns": False`: its names are the ones set by hand, which DHCP never replaces (2.1.10.20). A subnet's
             VLAN may repeat: a VLAN may have several subnets (2.1.10.18). And the global level (manual 1.10.4.24.3):
             the organisation's and the site's options, definitions and classes merged (merge_option_sets), with the
             netboot presets' classes after them, each preset's subnet naming its classes and each preset's
             reservation its marker (netboot_classes, 2.1.10.25).
    Inputs:  plan — a site's plan as site_plan returns it ({"vlans", "subnets" [with ranges and addresses],
             "org_options", "site_options"}).
    Returns: {"subnets": [dhcp.subnets entries, in the plan's order], "records": [{"name", "ip"}], "options",
             "option_defs", "client_classes" (the global level, lists)}.
    Fails:   never for a plan fabric wrote (KeyError on a malformed one).
    Feeds:   load_address_plan (an apply), planned_subnets (the firewall and the Kea tab between applies)."""
    access = {v["id"]: v.get("access") or "full" for v in plan.get("vlans") or []}
    subnets, records = [], []
    boot = netboot_classes(plan)
    for s in plan.get("subnets") or []:
        for a in s.get("addresses") or []:
            if a.get("dns") and a.get("name"):
                records.append({"name": a["name"], "ip": a["ip"]})
        if not s.get("dhcp"):
            continue
        entry = {"subnet": s["cidr"], "name": s["name"],
                 "pools": [f"{r['first']} - {r['last']}" for r in s.get("ranges") or [] if r["kind"] == "dhcp"],
                 "reservations": []}
        if s.get("id"):
            entry["id"] = s["id"]
        for key, value in (("vlan", s.get("vlan")), ("notes", s.get("notes")), ("routers", s.get("gateway")),
                           ("relay", s.get("relay")), ("allow_overlap", s.get("allow_overlap")),
                           ("options", s.get("options"))):
            if value:
                entry[key] = value
        if access.get(s.get("vlan")) == "guest":
            entry["access"] = "guest"
        if boot["subnets"].get(s["name"]):
            entry["netboot_classes"] = boot["subnets"][s["name"]]
        for a in s.get("addresses") or []:
            if a["kind"] != "reservation":
                continue
            r = {"mac": a["mac"], "ip": a["ip"]}
            if a.get("name"):
                r["hostname"] = a["name"]
            if a.get("options"):
                r["options"] = a["options"]
            if a.get("dns") and a.get("name"):
                r["ddns"] = False
            if boot["reservations"].get(a["ip"]):
                r["classes"] = boot["reservations"][a["ip"]]
            entry["reservations"].append(r)
        subnets.append(entry)
    merged = merge_option_sets(plan.get("org_options"), plan.get("site_options"))
    return {"subnets": subnets, "records": records, "options": merged["options"],
            "option_defs": merged["option_defs"], "client_classes": merged["client_classes"] + boot["classes"]}
