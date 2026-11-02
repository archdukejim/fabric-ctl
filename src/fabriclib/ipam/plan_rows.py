import ipaddress

COLUMNS = ("site", "vlan", "vlan_name", "location", "subnet", "ip", "kind", "range", "name", "mac", "owner", "dns",
           "lease", "notes")


def _range_of(subnet, ip):
    """Purpose: the kind of the subnet's range holding an address.
    Inputs:  subnet — a subnet's plan entry; ip — IPv4Address.
    Returns: str, the range's kind, "" outside every range.
    Fails:   never.
    Feeds:   plan_rows."""
    for r in subnet.get("ranges") or []:
        if ipaddress.ip_address(r["first"]) <= ip <= ipaddress.ip_address(r["last"]):
            return r["kind"]
    return ""


def plan_rows(plan, leases=None):
    """Purpose: a site's address table (manual 1.10.4.2, 1.10.4.9): every subnet's gateway and recorded addresses, and
             the live leases beside them (a lease on a recorded address fills its lease column; one on an address
             nobody recorded is a row of its own, kind "lease"), in address order.
    Inputs:  plan — the site's plan (site_plan: site, vlans, subnets with ranges and addresses); leases — list_leases'
             rows ({"ip", "mac", "hostname", "state", "expires"}) for this site, or None.
    Returns: list of dicts with the keys of COLUMNS (dns "yes" or "", lease "<state> until <expires>" or "").
    Fails:   never for a plan fabric wrote.
    Feeds:   show_plan, find_in_plan, export_plan, networks_view, scan_subnet."""
    names = {(v.get("location") or "", v["id"]): v["name"] for v in plan.get("vlans") or []}
    held = {lease["ip"]: lease for lease in leases or [] if lease.get("ip")}
    rows = []
    for s in plan.get("subnets") or []:
        net = ipaddress.ip_network(s["cidr"])
        where = s.get("location") or ""          # "" the DC's own (manual 1.10.4.46)
        base = {"site": plan["site"], "vlan": s.get("vlan") or "", "vlan_name": names.get((where, s.get("vlan")), ""),
                "location": where, "subnet": s["cidr"]}
        found = []
        if s.get("gateway"):
            found.append({"ip": s["gateway"], "kind": "gateway", "name": "", "mac": "", "owner": "", "dns": "",
                          "notes": ""})
        for a in s.get("addresses") or []:
            found.append({"ip": a["ip"], "kind": a["kind"], "name": a.get("name") or "", "mac": a.get("mac") or "",
                          "owner": a.get("owner") or "", "dns": "yes" if a.get("dns") else "",
                          "notes": a.get("notes") or ""})
        recorded = {f["ip"] for f in found}
        for ip, lease in held.items():
            if ipaddress.ip_address(ip) in net and ip not in recorded:
                found.append({"ip": ip, "kind": "lease", "name": lease.get("hostname") or "",
                              "mac": lease.get("mac") or "", "owner": "", "dns": "", "notes": ""})
        for f in found:
            ip = ipaddress.ip_address(f["ip"])
            lease = held.get(f["ip"])
            rows.append({**base, **f, "range": _range_of(s, ip),
                         "lease": f"{lease.get('state')} until {lease.get('expires')}" if lease else ""})
    return sorted(rows, key=lambda r: (str(r["site"]), ipaddress.ip_address(r["ip"])))
