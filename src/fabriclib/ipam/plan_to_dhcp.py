def plan_to_dhcp(plan):
    """Purpose: what Kea and fabric's DNS are rendered from, out of a site's plan (manual 1.10.4.5, 1.10.4.14): each
             subnet served by DHCP as the `dhcp.subnets` entry the Kea template and normalize_dhcp know (its id, name,
             VLAN, notes, access from its VLAN, gateway as router, relay, options, its dhcp ranges as pools and its
             reservations), and every address published in DNS (static, infrastructure, or a reservation beside the
             name DHCP registers in dhcp.<domain>, 2.1.10.17) as an A record of the site's zone (its PTR follows,
             dns/reverse_zones). A subnet's VLAN may repeat: a VLAN may have several subnets (2.1.10.18).
    Inputs:  plan — a site's plan as read_plan returns it ({"vlans", "subnets" [with ranges and addresses]}).
    Returns: {"subnets": [dhcp.subnets entries, in the plan's order], "records": [{"name", "ip"}]}.
    Fails:   never for a plan fabric wrote (KeyError on a malformed one).
    Feeds:   load_address_plan (an apply), planned_subnets (the firewall and the Kea tab between applies)."""
    access = {v["id"]: v.get("access") or "full" for v in plan.get("vlans") or []}
    subnets, records = [], []
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
        for a in s.get("addresses") or []:
            if a["kind"] != "reservation":
                continue
            r = {"mac": a["mac"], "ip": a["ip"]}
            if a.get("name"):
                r["hostname"] = a["name"]
            if a.get("options"):
                r["options"] = a["options"]
            entry["reservations"].append(r)
        subnets.append(entry)
    return {"subnets": subnets, "records": records}
