def reverse_by_hand(reverse):
    """Purpose: the reverse names whose PTR is set by hand, by zone: every PTR fabric generates comes from a forward
             record of fabric's zones (the settings' `dns:` and the address manager's published names), so DHCP's
             key is denied each of them in BIND (2.1.10.20: a name set by hand is never replaced by DHCP's).
    Inputs:  reverse — reverse_zones()'s result ({"zones": {zone: [{"label", ...}]}}).
    Returns: {zone: [label, ...]} (zones without a PTR left out).
    Fails:   never.
    Feeds:   deploy/apply_deployment and dns/publish_zone_list (`reverse_by_hand` for bind9/config/named.conf.zones.j2:
             a `deny "kea-ddns"` rule per name before the zone's grant)."""
    return {zone: [r["label"] for r in recs] for zone, recs in (reverse.get("zones") or {}).items() if recs}
