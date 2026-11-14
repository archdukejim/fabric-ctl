import copy

from fabriclib.dns.alias_grants import alias_grants


def tsig_record_notice(data, zone_key, rtype, record):
    """Purpose: The TSIG keys a new record gives a right: a CNAME pointing at a record a key holds with its aliases
             (or at one of its aliases) lets that key update the CNAME's `_acme-challenge` at the next DNS' Apply
             (decision 2.1.4.14, manual 1.4.1.9.4: shown on the record form, the Review's row and in the audit).
    Inputs:  data — the vars now (domain, dns, tsig_keys); zone_key — the zone's key in `dns:`; rtype — the new
             record's type; record — its fields: name, and canonical, target or value (the CNAME's target).
    Returns: sorted list of the keys' names; [] for any other type, or when no key gains the name.
    Fails:   never.
    Feeds:   add_record (the audit), agent/pending_dns (the Review's row)."""
    if rtype != "CNAME" or not isinstance(record, dict) or not data.get("tsig_keys"):
        return []
    name = str(record.get("name") or "").strip().lower()
    target = str(record.get("canonical") or record.get("target") or record.get("value") or "").strip()
    if not name or not target:
        return []
    after = copy.deepcopy(data)
    zone = ((after.get("dns") or {}).get(zone_key))
    if not isinstance(zone, dict):
        return []
    zone.setdefault("CNAME", []).append({"name": name, "canonical": target})
    was = alias_grants(data)
    now = alias_grants(after)
    return sorted(k for k, covered in now.items()
                  if any(name in names for names in covered.values())
                  and not any(name in names for names in was.get(k, {}).values()))
