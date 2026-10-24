import os

from fabriclib.dns.common.zone_records import zone_records

# what a name can hold that a resolver caches (the SOA left out: its serial moves with every change)
TYPES = {"A", "AAAA", "CNAME", "DNAME", "PTR", "TXT", "MX", "SRV", "NS", "CAA", "NAPTR", "HTTPS", "SVCB"}
MAX_NAMES = 50          # more changed names in one zone: the zone's whole subtree is flushed instead


def changed_names(zones):
    """Purpose: the names whose records an apply or Sync now is about to change (decision 2.1.10.46, manual
             1.10.4.44): each changed zone's rendered file compared with the deployed one before it is swapped in,
             name by name, so the filtering resolver can forget exactly those (flush_published_names).
    Inputs:  zones — [(zone, rendered file, deployed file)] (find_changed_zones' result), read before any is
             installed.
    Returns: {"names": sorted owner names with a trailing dot (added, changed or removed), "trees": sorted zones
             flushed whole (new: no deployed file yet; or more than MAX_NAMES names changed)}.
    Fails:   OSError reading a file.
    Feeds:   deploy/apply_deployment (an apply), dns/apply_dns (DNS' own Apply), dns/publish_plan_records (Sync
             now)."""
    names, trees = set(), set()
    for zone, src, dst in zones:
        if not os.path.exists(dst):
            trees.add(zone)
            continue
        with open(src) as f:
            new = set(zone_records(f.read(), zone, TYPES))
        with open(dst) as f:
            old = set(zone_records(f.read(), zone, TYPES))
        owners = {owner for owner, _, _ in new ^ old}
        if len(owners) > MAX_NAMES:
            trees.add(zone)
        else:
            names |= owners
    return {"names": sorted(names), "trees": sorted(trees)}
