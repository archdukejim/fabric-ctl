import ipaddress

WIDTH = 1000          # the bar's width in its own units (the console draws it as SVG, no inline style: CSP)


def _hosts(net):
    """Purpose: a subnet's usable addresses as integers (its network and broadcast addresses left out where it has
             them).
    Inputs:  net — IPv4Network.
    Returns: (first, last) ints.
    Fails:   never.
    Feeds:   subnet_map."""
    first, last = int(net.network_address), int(net.broadcast_address)
    return (first + 1, last - 1) if net.prefixlen < 31 else (first, last)


def _range_at(ranges, n):
    """Purpose: the kind of the range holding an address.
    Inputs:  ranges — [(first int, last int, kind)]; n — int.
    Returns: str, "" outside every range.
    Fails:   never.
    Feeds:   subnet_map."""
    return next((k for a, b, k in ranges if a <= n <= b), "")


def _free_rows(net, ranges, used, base):
    """Purpose: the free addresses of a subnet as rows, one per run of free addresses inside one range (or outside
             every range), so a /16 is a handful of rows, never 65,000.
    Inputs:  net — IPv4Network; ranges — [(first, last, kind)]; used — set of ints in use; base — the row's site,
             VLAN and subnet columns.
    Returns: list of rows (kind "free", ip the run's first address, "last" its last, "count").
    Fails:   never.
    Feeds:   subnet_map."""
    lo, hi = _hosts(net)
    points = {lo, hi + 1}
    for a, b, _ in ranges:
        points |= {max(a, lo), min(b, hi) + 1}
    for u in used:
        if lo <= u <= hi:
            points |= {u, u + 1}
    points = sorted(p for p in points if lo <= p <= hi + 1)
    rows = []
    for a, b in zip(points, points[1:]):
        if a in used:
            continue
        rows.append({**base, "ip": str(ipaddress.ip_address(a)), "last": str(ipaddress.ip_address(b - 1)),
                     "count": b - a, "kind": "free", "range": _range_at(ranges, a), "name": "", "mac": "",
                     "owner": "", "dns": "", "lease": "", "notes": "", "unrecorded": False})
    return rows


def subnet_map(subnet, rows):
    """Purpose: one subnet as the Networks tab draws it (manual 1.10.4.9): its ranges as a bar (each range's share of
             the subnet and how much of it is in use, gaps between ranges as "none"), its counts, and its address
             table with every address accounted for: the plan's entries, Kea's leases beside them, a lease on an
             address the plan does not hold marked "unrecorded", and the free addresses as runs.
    Inputs:  subnet — the subnet's plan entry (cidr, ranges); rows — plan_rows' rows of this subnet (gateway,
             recorded addresses, leases; kind "lease" for a lease nobody recorded).
    Returns: {"bar": [{"kind", "first", "last", "size", "used", "x", "w", "uw"}] (x, w and the used part uw in
             WIDTH units), "counts": {"size", "used", "free", "leases", "recorded", "unrecorded"}, "rows": the table
             in address order (each row with "unrecorded" (bool) and, for a free run, "last" and "count")}.
    Fails:   ValueError for a subnet whose cidr is not a network (never for a plan fabric wrote).
    Feeds:   networks_view."""
    net = ipaddress.ip_network(subnet["cidr"])
    lo, hi = _hosts(net)
    size = hi - lo + 1
    ranges = sorted((int(ipaddress.ip_address(r["first"])), int(ipaddress.ip_address(r["last"])), r["kind"])
                    for r in subnet.get("ranges") or [])
    table = [{**r, "unrecorded": r["kind"] == "lease"} for r in rows]
    used = {int(ipaddress.ip_address(r["ip"])) for r in table}
    base = {k: (rows[0][k] if rows else "") for k in ("site", "vlan", "vlan_name", "location", "subnet")} if rows else {
        "site": "", "vlan": subnet.get("vlan") or "", "vlan_name": "", "location": subnet.get("location") or "",
        "subnet": subnet["cidr"]}
    table += _free_rows(net, ranges, used, base)
    table.sort(key=lambda r: int(ipaddress.ip_address(r["ip"])))
    bar, at = [], lo
    for a, b, kind in ranges + [(hi + 1, hi + 1, "")]:
        a, b = max(a, lo), min(b, hi)
        if a > at:
            bar.append({"kind": "none", "first": at, "last": a - 1})
        if kind and a <= b:
            bar.append({"kind": kind, "first": a, "last": b})
        at = max(at, b + 1)
    for seg in bar:
        seg["size"] = seg["last"] - seg["first"] + 1
        seg["used"] = sum(1 for u in used if seg["first"] <= u <= seg["last"])
        seg["x"] = round((seg["first"] - lo) * WIDTH / size, 1)
        seg["w"] = max(round(seg["size"] * WIDTH / size, 1), 0.5)
        seg["uw"] = round(seg["used"] * WIDTH / size, 1)
        seg["first"], seg["last"] = str(ipaddress.ip_address(seg["first"])), str(ipaddress.ip_address(seg["last"]))
    in_use = sum(1 for u in used if lo <= u <= hi)
    counts = {"size": size, "used": in_use, "free": size - in_use,
              "leases": sum(1 for r in rows if r.get("lease") or r["kind"] == "lease"),
              "recorded": sum(1 for r in rows if r["kind"] not in ("lease", "gateway")),
              "unrecorded": sum(1 for r in rows if r["kind"] == "lease")}
    return {"bar": bar, "counts": counts, "rows": table}
