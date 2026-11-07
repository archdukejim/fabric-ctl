from fabriclib.dns.common.own_names import own_names


def fabric_record(v, key, rtype, record):
    """Purpose: whether a record is one of fabric's own names (2.1.2.22 item 6): the site's zone gets them back from
             their settings on every render, so the DNS tab marks them "provided by fabric" and a delete is refused.
    Inputs:  v — the settings (as own_names reads them); key — the zone key (only dynamic_zone_var, the site's zone,
             holds fabric's names); rtype — the record's type; record — the record dict (name, canonical or ip).
    Returns: {"service", "setting"} when the record is fabric's (its name and what it points to both match), else None.
    Fails:   never.
    Feeds:   dns/zone_detail (the pill), dns/remove_record (the refusal)."""
    if key != "dynamic_zone_var" or not isinstance(record, dict):
        return None
    hit = own_names(v).get((rtype, str(record.get("name") or "")))
    value = str((record.get("canonical") if rtype == "CNAME" else record.get("ip")) or "")
    if not hit or value.rstrip(".") != hit[0]:
        return None
    return {"service": hit[1], "setting": hit[2]}
