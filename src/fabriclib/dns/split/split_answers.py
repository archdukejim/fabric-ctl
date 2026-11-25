import re

import ipaddress

from fabriclib.dns.common.fabric_record import fabric_record
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.ptr_for_ip import ptr_for_ip
from fabriclib.dns.split.offered_subnets import offered_subnets
from fabriclib.dns.split.zone_networks import ALL, zone_networks
from fabriclib.dns.zone_name import zone_name

GONE = "CNAME ."            # RPZ local data for "no such name"


def _qualified(target, zone):
    """Purpose: a record's target as the zone file reads it, written out in full for an RPZ (whose origin is not
             the zone's): a name ending in a dot as it is, any other relative to the zone.
    Inputs:  target — str; zone — the zone's name.
    Returns: str ending in a dot.
    Fails:   never.
    Feeds:   _rdata."""
    target = str(target or "").strip()
    return target if target.endswith(".") else f"{target}.{zone}."


def _rdata(rtype, rec, zone):
    """Purpose: one record's type and data as an RPZ's local data writes them (bind9/data/zone.j2's, in full).
    Inputs:  rtype — the record's type; rec — its fields; zone — the zone's name.
    Returns: str, "<TYPE> <data>".
    Fails:   never.
    Feeds:   _tab."""
    if rtype in ("A", "AAAA"):
        return f"{rtype} {rec.get('ip')}"
    if rtype == "CNAME":
        return f"CNAME {_qualified(rec.get('canonical'), zone)}"
    if rtype == "MX":
        return f"MX {rec.get('priority')} {_qualified(rec.get('exchange'), zone)}"
    if rtype == "TXT":
        return f'TXT "{rec.get("text")}"'
    return f"SRV {rec.get('priority')} {rec.get('weight')} {rec.get('port')} {_qualified(rec.get('target'), zone)}"


def _tab(v, key, home, name, own):
    """Purpose: one tab's answers by owner name: its records, and the PTR of each A or AAAA record with a private
             address (ptr_for_ip); fabric's own names left out (they answer in every tab as the zone file has them).
    Inputs:  v — settings; key — the zone's key; home — the tab's record lists (the zone, or a split); name — the
             zone's name; own — a set the owners of fabric's own names are added to.
    Returns: {owner or reverse owner: set of rdata}.
    Fails:   never.
    Feeds:   split_answers."""
    out = {}
    for rtype in RECORD_TYPES:
        for rec in home.get(rtype) or []:
            if not isinstance(rec, dict):
                continue
            owner = name if rec.get("name") in ("@", "", None) else f"{rec.get('name')}.{name}"
            if fabric_record(v, key, rtype, rec):
                own.add(owner)
                continue
            out.setdefault(owner, set()).add(_rdata(rtype, rec, name))
            if rtype in ("A", "AAAA"):
                zone_of, label = ptr_for_ip(rec.get("ip"))
                if zone_of is not None:
                    out.setdefault(f"{label}.{zone_of}", set()).add(f"PTR {owner}.")
    return out


def _diff(base, tab, skip):
    """Purpose: what a split's RPZ says for its zone: each owner whose answers differ from the All networks tab's,
             with the split's answers, or "no such name" when the split lacks it.
    Inputs:  base, tab — {owner: set of rdata} (_tab); skip — owners never touched (fabric's own names).
    Returns: {owner: sorted rdata}.
    Fails:   never.
    Feeds:   split_answers."""
    out = {}
    for owner in list(base) + [o for o in tab if o not in base]:
        if owner in skip or base.get(owner) == tab.get(owner):
            continue
        out[owner] = sorted(tab[owner]) if owner in tab else [GONE]
    return out


def _put(lines, found):
    """Purpose: add one zone's answers to a network's, an answer winning over another zone's "no such name" for the
             same owner (a reverse name two zones share).
    Inputs:  lines — {owner: [rdata]} kept so far (changed in place); found — {owner: [rdata]}.
    Returns: None.
    Fails:   never.
    Feeds:   split_answers."""
    for owner, data in found.items():
        have = lines.get(owner)
        if have is None or have == [GONE]:
            lines[owner] = list(data)
        elif data != [GONE]:
            lines[owner] = sorted(set(have) | set(data))


def _entry(ref, view, rpz, cidrs, lines):
    """Purpose: one view's answers as the templates take them.
    Inputs:  ref — its network (or "rest"); view — its view's name; rpz — its RPZ's name; cidrs — its match;
             lines — {owner: [rdata]}.
    Returns: {"ref", "view", "rpz", "cidrs", "names" (the owners that are not reverse names), "lines"
             (["<owner> <TYPE> <data>"], the owner relative to the RPZ, so "www.home.arpa" for www in home.arpa)}.
    Fails:   never.
    Feeds:   split_answers."""
    return {"ref": ref, "view": view, "rpz": rpz, "cidrs": cidrs,
            "names": [o for o in lines if not o.endswith(".arpa")],
            "lines": [f"{o} {d}" for o in lines for d in lines[o]]}


def _zones(v):
    """Purpose: each mapped or split forward zone's answers, worked out once: its networks, each split's networks
             with what its RPZ says, and what hiding the zone says.
    Inputs:  v — settings.
    Returns: [(networks ("all" or [CIDR]), [(set of the split's CIDRs, {owner: [rdata]})], {owner: [GONE]})].
    Fails:   never.
    Feeds:   split_answers."""
    out = []
    for key, zone in (v.get("dns") or {}).items():
        if not isinstance(zone, dict) or str(key).endswith(".arpa"):
            continue
        mapped = zone_networks(zone)
        splits = [s for s in zone.get("splits") or [] if isinstance(s, dict)]
        if mapped == ALL and not splits:
            continue
        name, own = zone_name(v, key), set()
        base = _tab(v, key, zone, name, own)
        tabs = [(set(s.get("subnets") or []), _diff(base, _tab(v, key, s, name, set()), own)) for s in splits]
        hide = {name: [GONE], f"*.{name}": [GONE], **{o: [GONE] for o in base if o.endswith(".arpa")}}
        out.append((mapped, tabs, hide))
    return out


def split_answers(v, plan=None):
    """Purpose: the networks with answers of their own (decision 2.1.4.18, manual 1.4.1.13): each network some zone
             is mapped to or split for gets a view, whose RPZ holds, per zone, "no such name" for a zone mapped to
             other networks, or the differences between its split's records and the All networks tab's (with their
             PTRs). A client in none of those networks (the rest) gets "no such name" for every mapped zone.
    Inputs:  v — rendered settings (domain, lan_cidr, dns: each zone may carry "networks" and "splits"); plan — the
             site's plan (default: the copy this site last read).
    Returns: {"views": [_entry: "ref" (the network), "view" ("subnet-<cidr>", "." and "/" as "-"), "rpz"
             ("split-<cidr>.rpz"), "cidrs" ([the network])], the most specific network first (BIND and the resolver
             take the first view that matches); "rest": _entry ("rest", "everyone", "split-rest.rpz", ["any"]) when
             a zone is mapped, else None}. A network neither the host's LAN nor in the plan any more is left out (it
             answers as the rest until it is back).
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   deploy/render_templates (BIND's views and RPZ files), dns_filter/resolver_views (the resolver's)."""
    zones = _zones(v)
    if not zones:
        return {"views": [], "rest": None}
    known = [o["cidr"] for o in offered_subnets(v, plan)]
    nets = {c for mapped, _, _ in zones if mapped != ALL for c in mapped}
    nets |= {c for _, tabs, _ in zones for cidrs, _ in tabs for c in cidrs}
    views = []
    for cidr in sorted((c for c in nets if c in known),
                       key=lambda c: (-ipaddress.ip_network(c).prefixlen, known.index(c))):
        lines = {}
        for mapped, tabs, hide in zones:
            if mapped != ALL and cidr not in mapped:
                _put(lines, hide)
                continue
            for cidrs, found in tabs:
                if cidr in cidrs:
                    _put(lines, found)
        safe = re.sub(r"[^a-z0-9-]", "-", cidr.lower())
        views.append(_entry(cidr, f"subnet-{safe}", f"split-{safe}.rpz", [cidr], lines))
    rest = {}
    for mapped, _, hide in zones:
        if mapped != ALL:
            _put(rest, hide)
    return {"views": views, "rest": _entry("rest", "everyone", "split-rest.rpz", ["any"], rest) if rest else None}
