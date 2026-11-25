from fabriclib.common.errors import ValidationError
from fabriclib.dns.split.norm_subnet import norm_subnet
from fabriclib.dns.split.zone_networks import ALL, zone_networks

NEEDS_FILTER = ("split DNS needs the DNS filter on: a mapped or split zone is answered through the resolver's views, "
                "and the Windows domain's zone only there (2.1.4.16, 2.1.4.18); turn the filter on in the setup "
                "wizard first")


def filter_on(v, dns_filter=None):
    """Purpose: whether the DNS filter is on (dns_filter: bind), which split DNS needs (2.1.4.16's settled point).
    Inputs:  v — settings; dns_filter — a value to check instead of v's (a change checked before it is saved).
    Returns: bool; an unset filter is on (bind is the default).
    Fails:   never.
    Feeds:   needs_filter, split_needs_filter."""
    state = v.get("dns_filter") if dns_filter is None else dns_filter
    return str(state or "bind").strip().lower() == "bind"


def needs_filter(v):
    """Purpose: refuse mapping or splitting a zone while the DNS filter is off (2.1.4.18).
    Inputs:  v — settings.
    Returns: None.
    Fails:   ValidationError NEEDS_FILTER.
    Feeds:   set_zone_networks, add_split, update_split."""
    if not filter_on(v):
        raise ValidationError(NEEDS_FILTER)


def forward_only(key):
    """Purpose: refuse a reverse zone (1.4.1.13): its PTRs follow the records of the zones they name.
    Inputs:  key — the zone's key in `dns:`.
    Returns: None.
    Fails:   ValidationError for a key ending in .arpa.
    Feeds:   set_zone_networks, add_split."""
    if str(key).endswith(".arpa"):
        raise ValidationError("a reverse zone is never split or mapped: its PTRs follow the records they name")


def pick_networks(text, offered, allow_all=True):
    """Purpose: networks as typed or ticked (1.4.1.13), checked against those offered.
    Inputs:  text — "all", or CIDRs separated by commas or spaces; offered — [CIDR] (offered_subnets' cidrs);
             allow_all — False for a split, which names networks.
    Returns: "all", or the sorted CIDRs, each once and written as its network.
    Fails:   ValidationError: none picked; every network beside a network (or at all, for a split); not a subnet; one
             neither the host's LAN nor in the site's plan.
    Feeds:   set_zone_networks, add_split, update_split."""
    words = str(text or "").replace(",", " ").split()
    if not words:
        raise ValidationError("pick at least one network")
    if any(w.lower() == ALL for w in words):
        if not allow_all:
            raise ValidationError("a split names networks, never every network: that is the All networks tab")
        if len(words) > 1:
            raise ValidationError("every network already holds the others: pick it alone")
        return ALL
    out = set()
    for w in words:
        cidr = norm_subnet(w) if "/" in w else ""
        if not cidr:
            raise ValidationError(f"{w} is not a subnet (write it as 10.1.20.0/24)")
        if cidr not in offered:
            raise ValidationError(f"{cidr} is neither the host's LAN nor a subnet of the site's plan")
        out.add(cidr)
    return sorted(out)


def free_networks(zone, nets, skip=None):
    """Purpose: refuse a split network the zone does not answer, or one another split of the zone already holds.
    Inputs:  zone — the zone; nets — the split's CIDRs; skip — the index of the split being changed (its own
             networks are free for it).
    Returns: None.
    Fails:   ValidationError naming the network.
    Feeds:   add_split, update_split."""
    mapped = zone_networks(zone)
    for cidr in nets:
        if mapped != ALL and cidr not in mapped:
            raise ValidationError(f"{cidr} is not one of the zone's networks: add it to them first")
        for i, s in enumerate(zone.get("splits") or []):
            if i != skip and cidr in (s.get("subnets") or []):
                raise ValidationError(f"{cidr} is already in another split of this zone")
