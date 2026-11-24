from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.rules.rule_networks import rule_networks


def vlan_records_to_subnets(data, plan=None):
    """Purpose: the upgrade step of 2.1.4.17: a DNS record that 0.10.0 gave to one VLAN (`vlan`) answers that VLAN's
             subnets instead (`subnets`), so it keeps the reach it had. Acts only on positive evidence: a record
             carrying `vlan`; every other record, and a fresh install, is left as it is (a record without `subnets`
             answers every subnet, as before).
    Inputs:  data — settings (an existing install's vars; modified in place); plan — the site's plan (default: the
             copy this site last read; none kept: the VLAN's subnets are unknown).
    Returns: list of change descriptions (str), one per record moved; empty when no record names a VLAN.
    Fails:   never for a missing plan copy (a record whose VLAN has no known subnet gets none: it answered no one
             before, and still does until subnets are picked for it); OSError or json errors for a damaged one.
    Feeds:   setup/upgrade_vars."""
    zones = data.get("dns") if isinstance(data.get("dns"), dict) else {}
    found = [(key, rtype, rec) for key, zone in zones.items() if isinstance(zone, dict) for rtype in RECORD_TYPES
             for rec in zone.get(rtype) or [] if isinstance(rec, dict) and "vlan" in rec]
    if not found:
        return []
    plan = load_plan_cache() if plan is None else plan
    nets = rule_networks(data, plan or {})["vlans"]
    changes = []
    for key, rtype, rec in found:
        ref = str(rec.pop("vlan") or "")
        if not ref:                     # an empty vlan answered everyone: it still does
            continue
        rec["subnets"] = sorted(nets.get(ref) or [])
        where = ", ".join(rec["subnets"]) or f"no subnet (VLAN {ref} has none in the plan: pick some in the console)"
        changes.append(f"DNS {rtype} {rec.get('name')} in {key}: VLAN {ref}'s record now answers {where} (2.1.4.17)")
    return changes
