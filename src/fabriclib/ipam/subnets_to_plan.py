import ipaddress

# what a 0.7 subnet carries that the plan holds; anything else is listed as not carried (manual 1.10.4.15)
KNOWN = {"subnet", "id", "name", "vlan", "notes", "allow_overlap", "access", "relay", "pools", "routers", "options",
         "reservations", "server", "interface"}


def _label(net):
    """Purpose: a name for a subnet that had none: its network as one DNS label.
    Inputs:  net — IPv4Network.
    Returns: str, e.g. "net-10-1-20-0-24".
    Fails:   never.
    Feeds:   subnets_to_plan."""
    return "net-" + str(net.network_address).replace(".", "-") + f"-{net.prefixlen}"


def subnets_to_plan(subnets, plan, site):
    """Purpose: the upgrade from 0.7 and 0.8.0 (manual 1.10.4.10, 1.10.4.15, 1.10.4.37): a site's `dhcp.subnets`
             (normalized) as the plan's changes, nothing a running site serves changed: each subnet a VLAN (its own VLAN
             ID; one without gets the lowest free ID and is listed for the admin) and the VLAN's subnet, served by DHCP,
             keeping its Kea id, name, router (the gateway, and a one-address gateway range unless a pool holds it),
             relay, notes, overlap reason, access and options; each pool a dhcp range; each reservation a reservation
             address with its hostname and options. A subnet the plan already has (by name or network) is left as it is,
             so a second run changes nothing; one convergence wrote before (a fabricNetwork entry of that name) is
             converted in place.
    Inputs:  subnets — normalize_dhcp's subnets; plan — the site's plan (read_plan: "vlans", "subnets", "networks");
             site — the site's name.
    Returns: {"changes": [write_plan changes], "moved": [{"subnet", "name", "vlan"}], "assigned": [{"subnet", "vlan"}]
             (VLAN IDs fabric chose), "kept": [names already in the plan], "not_carried": ["<subnet>: <key>"]}.
    Fails:   never for normalized subnets.
    Feeds:   move_subnets_to_plan."""
    out = {"changes": [], "moved": [], "assigned": [], "kept": [], "not_carried": []}
    used_ids = {v["id"] for v in plan.get("vlans") or []}
    used_names = {v["name"] for v in plan.get("vlans") or []}
    have = {s["name"] for s in plan.get("subnets") or []} | {s["cidr"] for s in plan.get("subnets") or []}
    legacy = {n["name"] for n in plan.get("networks") or []}
    for s in subnets:
        net = ipaddress.ip_network(s["subnet"])
        name = s.get("name") or _label(net)
        if name in have or str(net) in have:
            out["kept"].append(name)
            continue
        out["not_carried"] += [f"{net}: {k}" for k in s if k not in KNOWN]
        vid = s.get("vlan")
        if vid is None:
            vid = next(n for n in range(1, 4095) if n not in used_ids)
            out["assigned"].append({"subnet": str(net), "vlan": vid})
        if vid not in used_ids:
            vname = name if name not in used_names else f"{name}-{vid}"
            out["changes"].append({"do": "add", "what": "vlan", "site": site, "key": str(vid),
                                   "fields": {"id": vid, "name": vname, "access": s.get("access") or "full",
                                              "purpose": "", "notes": ""}})
            used_ids.add(vid)
            used_names.add(vname)
        pools = [tuple(ipaddress.ip_address(p.strip()) for p in str(pool).split("-")) for pool in s.get("pools") or []]
        router = s.get("routers") or ""
        fields = {"cidr": str(net), "vlan": vid, "kind": "dhcp", "gateway": router, "dhcp": True, "id": s.get("id"),
                  "relay": s.get("relay") or "", "notes": s.get("notes") or "",
                  "allow_overlap": s.get("allow_overlap") or "", "options": s.get("options") or []}
        out["changes"].append({"do": "set" if name in legacy else "add", "what": "subnet", "site": site,
                               "key": name, "fields": fields})
        for lo, hi in pools:
            out["changes"].append({"do": "add", "what": "range", "site": site, "subnet": name, "key": f"dhcp-{lo}",
                                   "fields": {"kind": "dhcp", "first": str(lo), "last": str(hi), "notes": ""}})
        if router and not any(lo <= ipaddress.ip_address(router) <= hi for lo, hi in pools):
            out["changes"].append({"do": "add", "what": "range", "site": site, "subnet": name,
                                   "key": f"gateway-{router}",
                                   "fields": {"kind": "gateway", "first": router, "last": router, "notes": ""}})
        for r in s.get("reservations") or []:
            out["changes"].append({"do": "add", "what": "address", "site": site, "subnet": name, "key": r["ip"],
                                   "fields": {"ip": r["ip"], "kind": "reservation", "name": r.get("hostname") or "",
                                              "mac": r["mac"], "dns": False, "options": r.get("options") or []}})
        out["moved"].append({"subnet": str(net), "name": name, "vlan": vid})
    return out
