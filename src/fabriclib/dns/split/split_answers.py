import re

from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.rules.rule_networks import rule_networks


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
    """Purpose: the VLANs with answers of their own (decision 2.1.4.16, manual 1.4.1.11): for each, its subnets and
             its records as an RPZ's local data, which the resolver's views and BIND's own give that VLAN's clients
             in place of the zone's answers for the same names.
    Inputs:  v — rendered settings (domain, dns: each record may carry "vlan", a VLAN reference of the site's plan);
             plan — the site's plan (default: the copy this site last read, load_plan_cache).
    Returns: [{"ref" (the VLAN's reference), "view" ("vlan-<ref>", "@" as "-"), "rpz" ("split-<ref>.rpz"),
             "cidrs" (its subnets), "names" ([fqdn]), "lines" (["<owner> <TYPE> <data>"], the owner relative to the
             RPZ, so "www.home.arpa" for www in home.arpa)}], in the plan's VLAN order; a VLAN with no subnet, or
             one the plan no longer has, is left out (its records answer no one until it has).
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   deploy/render_templates (BIND's views and RPZ files), dns_filter/deploy_resolver (the resolver's)."""
    plan = load_plan_cache() if plan is None else plan
    nets = rule_networks(v, plan or {})["vlans"]
    found = {}
    for key, zone in (v.get("dns") or {}).items():
        name = v.get("domain") if key == "dynamic_zone_var" else key
        for rtype in RECORD_TYPES:
            for rec in (zone or {}).get(rtype) or []:
                ref = str(rec.get("vlan") or "")
                if not ref or not nets.get(ref):
                    continue
                owner = name if rec.get("name") == "@" else f"{rec.get('name')}.{name}"
                found.setdefault(ref, []).append((owner, _rdata(rtype, rec, name)))
    out = []
    for ref in nets:
        if ref not in found:
            continue
        safe = re.sub(r"[^a-z0-9-]", "-", ref.lower())
        out.append({"ref": ref, "view": f"vlan-{safe}", "rpz": f"split-{safe}.rpz", "cidrs": list(nets[ref]),
                    "names": list(dict.fromkeys(o for o, _ in found[ref])),
                    "lines": [f"{o} {d}" for o, d in found[ref]]})
    return out
