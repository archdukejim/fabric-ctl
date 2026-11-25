from fabriclib.common.errors import ValidationError
from fabriclib.dns.split.split_checks import NEEDS_FILTER, filter_on
from fabriclib.dns.split.zone_networks import ALL, zone_networks
from fabriclib.dns.zone_name import zone_name


def split_zones(v):
    """Purpose: the zones answered by network (decision 2.1.4.18): mapped to some networks, or split.
    Inputs:  v — settings (vars.yaml, or rendered): its `dns` zones.
    Returns: list of str, "<zone> (mapped)", "<zone> (2 splits)" or both, in zone order; empty when none.
    Fails:   never.
    Feeds:   split_needs_filter."""
    out = []
    for key, zone in (v.get("dns") if isinstance(v.get("dns"), dict) else {}).items():
        if not isinstance(zone, dict):
            continue
        what = (["mapped"] if zone_networks(zone) != ALL else []) + \
            ([f"{len(zone['splits'])} split{'s' if len(zone['splits']) > 1 else ''}"] if zone.get("splits") else [])
        if what:
            out.append(f"{zone_name(v, key)} ({', '.join(what)})")
    return out


def split_needs_filter(v, dns_filter=None):
    """Purpose: refuse split DNS with the DNS filter off (decisions 2.1.4.16, 2.1.4.18; manual 1.4.1.13): the AD
             zone is Samba's DLZ, which loads into one of BIND's views, so only the resolver answers it for a network
             with answers of its own.
    Inputs:  v — settings with its `dns` zones; dns_filter — the filter's setting to check against (default: v's,
             "bind" when unset), so a change can be checked before it is saved.
    Returns: None.
    Fails:   ValidationError naming the mapped or split zones, when the filter is not bind and a zone is either.
    Feeds:   settings/plan_settings (the filter turned off), deploy/check_settings (every apply)."""
    names = split_zones(v)
    if names and not filter_on(v, dns_filter):
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        raise ValidationError(f"{NEEDS_FILTER}; zones answered by network: {shown}")
