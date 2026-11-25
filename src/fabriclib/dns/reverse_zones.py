from fabriclib.dns.ptr_for_ip import ptr_for_ip
from fabriclib.dns.zone_name import zone_name

REVERSE_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")


def reverse_zones(v):
    """Purpose: The reverse zones generated from every A and AAAA record in the forward zones.
    Inputs:  v — the vars dict; reads dns, domain (via zone_name), host_ip, each zone's zone_authority, and
             dhcp_reverse_zones (zones DHCP registers in: present even with no static record, 2.1.10.7).
    Returns: {"zones": {zone: [{"label", "target" (FQDN with trailing dot), "ip", "source"}]} sorted by zone and label,
             "skipped": [{"name", "ip", "reason"}] for addresses that get no PTR}.
    Fails:   never — addresses that cannot get a PTR are listed in "skipped".
    Feeds:   deploy/apply_deployment (render_templates renders them with bind9/data/reverse-zone.j2); agent route GET
             /v1/reverse-zones
             (fabric-agent, src/agent/); the web UI's dev preview (src/webui/devpreview).
    Notes:   one PTR per address: the first named record wins, then an apex (@) record, then the zone's `ns` host.
             Private IPv4 (RFC 1918, CGNAT) and IPv6 ULA only. A reverse zone written by hand in `dns:` is left alone.
             A split's records (2.1.4.18) get their PTRs in their networks' answers only (split_answers), so none
             here: only the All networks tab's (the zone's own) are read.
    """
    dns = v.get("dns") or {}
    manual = {k for k in dns if k.endswith(REVERSE_SUFFIXES)}
    candidates = []                        # (priority, order, zone, label, target, ip, source)
    skipped = []
    order = 0
    for key, recs in dns.items():
        if key in manual or not isinstance(recs, dict):
            continue
        fwd = zone_name(v, key)
        entries = [(rtype, r) for rtype in ("A", "AAAA") for r in recs.get(rtype) or []]
        if recs.get("zone_authority") and v.get("host_ip"):
            entries.append(("A", {"name": "ns", "ip": v["host_ip"], "_ns": True}))
        for rtype, rec in entries:
            order += 1
            name = str(rec.get("name") or "").strip()
            fqdn = f"{fwd}." if name in ("", "@") else f"{name}.{fwd}."
            zone, label = ptr_for_ip(rec.get("ip"))
            if zone is None:
                if not rec.get("_ns"):
                    skipped.append({"name": fqdn.rstrip("."), "ip": rec.get("ip"), "reason": label})
                continue
            if zone in manual:
                continue
            priority = 2 if rec.get("_ns") else (1 if name in ("", "@") else 0)
            candidates.append((priority, order, zone, label, fqdn, rec.get("ip"), f"{rtype} {name or '@'} in {fwd}"))
    zones, taken = {}, set()
    for priority, _, zone, label, target, ip, source in sorted(candidates):
        zones.setdefault(zone, [])
        if (zone, label) in taken:
            continue
        taken.add((zone, label))
        zones[zone].append({"label": label, "target": target, "ip": ip, "source": source})
    for zone in v.get("dhcp_reverse_zones") or []:
        if zone not in manual:
            zones.setdefault(zone, [])
    for recs in zones.values():
        recs.sort(key=lambda r: (0, int(r["label"]), "") if r["label"].isdigit() else (1, 0, r["label"]))
    return {"zones": dict(sorted(zones.items())), "skipped": skipped}
