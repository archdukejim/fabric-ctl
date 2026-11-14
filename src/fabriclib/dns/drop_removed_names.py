import datetime

from fabriclib.common.errors import ValidationError
from fabriclib.dns.key_record_choices import key_record_choices
from fabriclib.dns.tsig_key_mode import tsig_key_mode
from fabriclib.dns.zone_name import zone_name


def drop_removed_names(before, data, zone_key):
    """Purpose: A record removed from a zone takes its grant from every ACME (DNS-01) key of that zone (decision
             2.1.4.12: no grant is left to a name that no longer exists), with a note on the key; a name another
             record of the zone still has keeps its grant. Custom keys keep the names they were given.
    Inputs:  before — the vars before the removal; data — the vars after it, changed in place (tsig_keys);
             zone_key — the zone's key in `dns:`.
    Returns: [(key name, [names dropped])] for the audit; [] when no key named the record.
    Fails:   never.
    Feeds:   remove_record."""
    domain = zone_name(data, zone_key)
    try:
        old_choices = key_record_choices(before, domain)
        new_choices = key_record_choices(data, domain)
    except ValidationError:                             # the zone itself went: remove_zone refuses while keys name it
        return []
    names = {c["name"] for c in new_choices}
    addresses = {c["name"] for c in new_choices if c["address"]}
    today = datetime.date.today().isoformat()
    out = []
    for key in data.get("tsig_keys") or []:
        if (key.get("domain") or data.get("domain")) != domain or tsig_key_mode(key, old_choices) != "acme":
            continue
        gone = [r for r in key.get("records") or [] if str(r).lower() not in names]
        gone_aliases = [r for r in key.get("records_with_aliases") or [] if str(r).lower() not in addresses]
        if not gone and not gone_aliases:
            continue
        if gone:
            key["records"] = [r for r in key["records"] if r not in gone]
        if gone_aliases:
            key["records_with_aliases"] = [r for r in key["records_with_aliases"] if r not in gone_aliases]
        for field in ("records", "records_with_aliases"):
            if not key.get(field):
                key.pop(field, None)
        dropped = gone + [f"{r} and its aliases" for r in gone_aliases]
        key["notes"] = list(key.get("notes") or []) + [f"{today}: {', '.join(dropped)} dropped: the record was removed"]
        out.append((key["name"], dropped))
    return out
