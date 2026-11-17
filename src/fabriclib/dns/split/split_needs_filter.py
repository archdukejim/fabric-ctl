from fabriclib.common.errors import ValidationError
from fabriclib.dns.constants import RECORD_TYPES

WHY = ("split DNS needs the DNS filter on: with it off, clients of a VLAN with answers of its own get no answers "
       "for the Windows domain's zone and cannot register in it (2.1.4.16)")


def split_names(v):
    """Purpose: the records that answer one VLAN alone (decision 2.1.4.16), as "<name> (VLAN <ref>)".
    Inputs:  v — settings (vars.yaml, or rendered): its `dns` zones.
    Returns: list of str, in zone and type order; empty when no record names a VLAN.
    Fails:   never.
    Feeds:   split_needs_filter."""
    zones = v.get("dns") if isinstance(v.get("dns"), dict) else {}
    return [f"{r.get('name')} (VLAN {r['vlan']})" for zone in zones.values() if isinstance(zone, dict)
            for t in RECORD_TYPES for r in zone.get(t) or [] if isinstance(r, dict) and r.get("vlan")]


def split_needs_filter(v, dns_filter=None):
    """Purpose: refuse split DNS with the DNS filter off (decision 2.1.4.16, manual 1.4.1.11): the AD zone is
             Samba's DLZ, which loads into one of BIND's views, so only the resolver answers it for a split VLAN.
    Inputs:  v — settings with its `dns` zones; dns_filter — the filter's setting to check against (default: v's,
             "bind" when unset), so a change can be checked before it is saved.
    Returns: None.
    Fails:   ValidationError naming the split records, when the filter is not bind and any record names a VLAN.
    Feeds:   dns/split/record_vlan (a record given a VLAN), settings/plan_settings (the filter turned off),
             deploy/check_settings (every apply)."""
    state = str((v.get("dns_filter") if dns_filter is None else dns_filter) or "bind").strip().lower()
    names = split_names(v)
    if state != "bind" and names:
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        raise ValidationError(f"{WHY}; records for one VLAN: {shown}")
