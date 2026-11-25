ALL = "all"


def zone_networks(zone):
    """Purpose: the networks a zone answers (decision 2.1.4.18, manual 1.4.1.13): its `networks`, or every network.
    Inputs:  zone — one zone of the `dns:` setting (dict).
    Returns: "all" when it has no `networks` (every zone before 0.10.2 too), else the sorted list of CIDRs.
    Fails:   never.
    Feeds:   split_answers, split_checks (free_networks), set_zone_networks, split_needs_filter, dns/zone_detail."""
    nets = zone.get("networks") if isinstance(zone, dict) else None
    return ALL if nets is None else sorted(str(n) for n in nets)
