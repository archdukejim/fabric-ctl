from fabriclib.dns.zone_name import zone_name


def zone_records_for(data, domain):
    """Purpose: A zone's records as vars hold them (`dns:`), found by the zone's name (a TSIG key's `domain`).
    Inputs:  data — the vars (domain, dns); domain — str zone name, or empty for the site's own zone.
    Returns: the zone's dict ({type: [record]}, zone_authority, ...), or None when fabric has no such zone.
    Fails:   never.
    Feeds:   alias_grants, key_record_choices, tsig_key_mode, edit_tsig_names, drop_removed_names."""
    want = str(domain or data.get("domain") or "").rstrip(".").lower()
    for key, zone in (data.get("dns") or {}).items():
        if zone_name(data, key).rstrip(".").lower() == want:
            return zone or {}
    return None
