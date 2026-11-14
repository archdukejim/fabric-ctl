from fabriclib.common.errors import ValidationError
from fabriclib.dns.key_record_choices import key_record_choices


def acme_picks(data, zone, hosts, with_aliases):
    """Purpose: ACME (DNS-01) mode's picks checked against the zone's records (decision 2.1.4.12; with aliases,
             2.1.4.14).
    Inputs:  data — the vars (domain, dns); zone — the zone's name; hosts — names picked; with_aliases — A or AAAA
             records picked with their aliases.
    Returns: {"records": [...], "records_with_aliases": [...]} (only the lists that have names), lower case.
    Fails:   ValidationError "pick at least one of the zone's records", "… is not a record of …", "… is not an A or
             AAAA record of …".
    Feeds:   create_zone_tsig_key (the console's New key), run_tsig_command (`tsig add --mode acme`)."""
    choices = key_record_choices(data, zone)
    names = {c["name"] for c in choices}
    addresses = {c["name"] for c in choices if c["address"]}
    hosts = list(dict.fromkeys(h.strip().rstrip(".").lower() for h in hosts if h.strip()))
    with_aliases = list(dict.fromkeys(h.strip().rstrip(".").lower() for h in with_aliases if h.strip()))
    if not hosts and not with_aliases:
        raise ValidationError("pick at least one of the zone's records")
    for h in hosts:
        if h not in names:
            raise ValidationError(f"{h} is not a record of {zone}: ACME (DNS-01) mode offers only the zone's records "
                                  "(Custom names any)")
    for h in with_aliases:
        if h not in addresses:
            raise ValidationError(f"{h} is not an A or AAAA record of {zone}: only those are picked with their aliases")
    out = {}
    if hosts:
        out["records"] = hosts
    if with_aliases:
        out["records_with_aliases"] = with_aliases
    return out
