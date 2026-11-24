from fabriclib.dns.split.reach import ALL, reach


def default_records(zone):
    """Purpose: a zone's records as every subnet gets them (decision 2.1.4.17): those for some subnets left out, for
             they are answered in those subnets alone (split_answers).
    Inputs:  zone — one zone of the `dns:` setting ({type: [record]}, and keys such as zone_authority).
    Returns: a copy of the zone with each record list less its records for some subnets.
    Fails:   never.
    Feeds:   deploy/render_templates (bind9/data/zone.j2)."""
    return {k: ([r for r in recs if not (isinstance(r, dict) and reach(r) != ALL)] if isinstance(recs, list) else recs)
            for k, recs in (zone or {}).items()}
