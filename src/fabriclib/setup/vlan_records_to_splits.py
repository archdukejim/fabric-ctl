import copy

from fabriclib.dns.common.fabric_record import fabric_record
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.rules.rule_networks import rule_networks


def _split(data, key, zone, mine, subnets):
    """Purpose: one VLAN's split: the zone's records (fabric's own names left out) with the VLAN's in place of
             theirs for the same names, as 0.10.0 answered that VLAN by name (1.4.1.11).
    Inputs:  data — settings; key — the zone's key; zone — the zone (its VLAN records already taken out); mine —
             [(type, record)] the VLAN's records (vlan field gone); subnets — the VLAN's CIDRs.
    Returns: the split dict.
    Fails:   never.
    Feeds:   vlan_records_to_splits."""
    names = {str(rec.get("name") or "") for _, rec in mine}
    split = {"subnets": sorted(subnets)}
    for rtype in RECORD_TYPES:
        recs = [copy.deepcopy(r) for r in zone.get(rtype) or [] if isinstance(r, dict)
                and str(r.get("name") or "") not in names and not fabric_record(data, key, rtype, r)]
        recs += [rec for t, rec in mine if t == rtype]
        if recs:
            split[rtype] = recs
    return split


def vlan_records_to_splits(data, plan=None):
    """Purpose: the upgrade step of 2.1.4.18 (manual 1.4.1.13): the records 0.10.0 gave to a VLAN (`vlan`) become a
             split of their zone for that VLAN's subnets, so the VLAN's clients keep the answers they had. Acts only
             on positive evidence: a record carrying `vlan`; every other record, and a fresh install, is left as it
             is.
    Inputs:  data — settings (an existing install's vars; modified in place); plan — the site's plan (default: the
             copy this site last read; none kept: the VLANs' subnets are unknown).
    Returns: list of change descriptions (str), one per split made and one per VLAN dropped; empty when no record
             names a VLAN.
    Fails:   never for a missing plan copy (a VLAN with no known subnet answered no one before: its records are
             dropped, saying so); OSError or json errors for a damaged one.
    Feeds:   setup/upgrade_vars."""
    zones = data.get("dns") if isinstance(data.get("dns"), dict) else {}
    found = [key for key, zone in zones.items() if isinstance(zone, dict)
             and any(isinstance(r, dict) and "vlan" in r for t in RECORD_TYPES for r in zone.get(t) or [])]
    if not found:
        return []
    plan = load_plan_cache() if plan is None else plan
    nets = rule_networks(data, plan or {})["vlans"]
    changes = []
    for key in found:
        zone, vlans = zones[key], {}
        for rtype in RECORD_TYPES:
            kept = []
            for rec in zone.get(rtype) or []:
                ref = str(rec.pop("vlan", "") or "") if isinstance(rec, dict) else ""
                if ref:
                    vlans.setdefault(ref, []).append((rtype, rec))
                else:                   # no VLAN, or an empty one: it answered everyone, and still does
                    kept.append(rec)
            if kept:
                zone[rtype] = kept
            elif rtype in zone:
                del zone[rtype]
        for ref, mine in vlans.items():
            subnets = sorted(nets.get(ref) or [])
            names = ", ".join(dict.fromkeys(str(r.get("name")) for _, r in mine))
            if not subnets:
                changes.append(f"DNS {key}: VLAN {ref}'s records ({names}) dropped: the VLAN has no subnet in the "
                               f"plan, so they answered no one (2.1.4.18)")
                continue
            zone.setdefault("splits", []).append(_split(data, key, zone, mine, subnets))
            changes.append(f"DNS {key}: VLAN {ref}'s records ({names}) now a split for {', '.join(subnets)} "
                           f"(2.1.4.18)")
    return changes
