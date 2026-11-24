from fabriclib.common.errors import ValidationError
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.split.reach import ALL, reach

WHY = ("a record for some subnets needs the DNS filter on: with it off, clients of a subnet with answers of its own "
       "get no answers for the Windows domain's zone and cannot register in it (2.1.4.16, 2.1.4.17)")


def split_names(v):
    """Purpose: the records that answer some subnets alone (decision 2.1.4.17), as "<name> (<subnet>, ...)".
    Inputs:  v — settings (vars.yaml, or rendered): its `dns` zones.
    Returns: list of str, in zone and type order; empty when every record answers every subnet.
    Fails:   never.
    Feeds:   split_needs_filter."""
    zones = v.get("dns") if isinstance(v.get("dns"), dict) else {}
    return [f"{r.get('name')} ({', '.join(reach(r)) or 'no subnet'})"
            for zone in zones.values() if isinstance(zone, dict)
            for t in RECORD_TYPES for r in zone.get(t) or [] if isinstance(r, dict) and reach(r) != ALL]


def split_needs_filter(v, dns_filter=None):
    """Purpose: refuse split DNS with the DNS filter off (decisions 2.1.4.16, 2.1.4.17; manual 1.4.1.12): the AD
             zone is Samba's DLZ, which loads into one of BIND's views, so only the resolver answers it for a subnet
             with answers of its own.
    Inputs:  v — settings with its `dns` zones; dns_filter — the filter's setting to check against (default: v's,
             "bind" when unset), so a change can be checked before it is saved.
    Returns: None.
    Fails:   ValidationError naming the split records, when the filter is not bind and a record is for some
             subnets.
    Feeds:   dns/split/record_subnets (a record given subnets), settings/plan_settings (the filter turned off),
             deploy/check_settings (every apply)."""
    state = str((v.get("dns_filter") if dns_filter is None else dns_filter) or "bind").strip().lower()
    names = split_names(v)
    if state != "bind" and names:
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        raise ValidationError(f"{WHY}; records for some subnets: {shown}")
