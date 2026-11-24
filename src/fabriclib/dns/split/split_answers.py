import re

import ipaddress

from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.ptr_for_ip import ptr_for_ip
from fabriclib.dns.split.offered_subnets import offered_subnets
from fabriclib.dns.split.reach import ALL, reach


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
    Feeds:   split_answers."""
    if rtype in ("A", "AAAA"):
        return f"{rtype} {rec.get('ip')}"
    if rtype == "CNAME":
        return f"CNAME {_qualified(rec.get('canonical'), zone)}"
    if rtype == "MX":
        return f"MX {rec.get('priority')} {_qualified(rec.get('exchange'), zone)}"
    if rtype == "TXT":
        return f'TXT "{rec.get("text")}"'
    return f"SRV {rec.get('priority')} {rec.get('weight')} {rec.get('port')} {_qualified(rec.get('target'), zone)}"


def split_answers(v, plan=None):
    """Purpose: the subnets with answers of their own (decision 2.1.4.17, manual 1.4.1.12): for each, its records as an
             RPZ's local data, which the resolver's views and BIND's own give that subnet's clients in place of the
             zone's answers for the same names. An A or AAAA record's PTR goes in its subnets' RPZ too, and in no
             reverse zone, so a reverse lookup elsewhere does not give its name away (2.1.4.17, point 1).
    Inputs:  v — rendered settings (domain, lan_cidr, dns: each record may carry "subnets"); plan — the site's plan
             (default: the copy this site last read).
    Returns: [{"ref" (the subnet), "view" ("subnet-<cidr>", "." and "/" as "-"), "rpz" ("split-<cidr>.rpz"),
             "cidrs" ([the subnet]), "names" ([fqdn]), "lines" (["<owner> <TYPE> <data>"], the owner relative to the
             RPZ, so "www.home.arpa" for www in home.arpa)}], the most specific subnet first (BIND and the resolver
             take the first view that matches); a subnet neither the host's LAN nor in the plan any more is left out
             (its records answer no one until it is back).
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   deploy/render_templates (BIND's views and RPZ files), dns_filter/resolver_views (the resolver's)."""
    known = [o["cidr"] for o in offered_subnets(v, plan)]
    found = {}
    for key, zone in (v.get("dns") or {}).items():
        if not isinstance(zone, dict):
            continue
        name = v.get("domain") if key == "dynamic_zone_var" else key
        for rtype in RECORD_TYPES:
            for rec in zone.get(rtype) or []:
                subnets = reach(rec)
                if subnets == ALL:
                    continue
                owner = name if rec.get("name") in ("@", "", None) else f"{rec.get('name')}.{name}"
                lines = [(owner, _rdata(rtype, rec, name))]
                if rtype in ("A", "AAAA"):
                    zone_of, label = ptr_for_ip(rec.get("ip"))
                    if zone_of is not None:
                        lines.append((f"{label}.{zone_of}", f"PTR {owner}."))
                for cidr in subnets:
                    if cidr in known:
                        found.setdefault(cidr, []).extend(lines)
    out = []
    for cidr in sorted(found, key=lambda c: (-ipaddress.ip_network(c).prefixlen, known.index(c))):
        safe = re.sub(r"[^a-z0-9-]", "-", cidr.lower())
        out.append({"ref": cidr, "view": f"subnet-{safe}", "rpz": f"split-{safe}.rpz", "cidrs": [cidr],
                    "names": list(dict.fromkeys(o for o, d in found[cidr] if not d.startswith("PTR "))),
                    "lines": list(dict.fromkeys(f"{o} {d}" for o, d in found[cidr]))})
    return out
