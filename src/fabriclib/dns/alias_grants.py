from fabriclib.dns.record_aliases import record_aliases
from fabriclib.dns.zone_records_for import zone_records_for


def _is_address(zone, record):
    """Purpose: Whether a zone has an A or AAAA record of this name.
    Inputs:  zone — the zone's dict; record — str name.
    Returns: bool.
    Fails:   never.
    Feeds:   alias_grants."""
    want = str(record).lower()
    return any(isinstance(r, dict) and str(r.get("name") or "").lower() == want
               for t in ("A", "AAAA") for r in zone.get(t) or [])


def alias_grants(data):
    """Purpose: What each TSIG key's `records_with_aliases` grants now: each entry's record and its aliases as the
             zone is at this render (decision 2.1.4.14: the aliases follow the zone), for BIND's update-policy and
             for showing a key.
    Inputs:  data — the vars (domain, dns, tsig_keys: normalized, each with its domain).
    Returns: {key name: {record: [record, alias, ...]}} for every key with entries; a record no longer an A or
             AAAA of its zone covers nothing ([]).
    Fails:   never.
    Feeds:   deploy/check_rendered (BIND's grants, the apply's and the quick zone path's: `tsig_alias_grants`),
             list_tsig_keys, dns/tsig_record_notice."""
    out = {}
    for key in data.get("tsig_keys") or []:
        entries = key.get("records_with_aliases") or []
        if not entries:
            continue
        domain = key.get("domain") or data.get("domain") or ""
        zone = zone_records_for(data, domain) or {}
        out[key.get("name")] = {record: ([record] + record_aliases(zone, domain, record))
                                if _is_address(zone, record) else [] for record in entries}
    return out
