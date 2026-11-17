def default_records(zone):
    """Purpose: a zone's records as everyone gets them (decision 2.1.4.16): those given to one VLAN left out, for
             they are answered to that VLAN alone (split_answers).
    Inputs:  zone — one zone of the `dns:` setting ({type: [record]}, and keys such as zone_authority).
    Returns: a copy of the zone with each record list less its VLAN's records.
    Fails:   never.
    Feeds:   deploy/render_templates (bind9/data/zone.j2)."""
    return {k: ([r for r in recs if not (isinstance(r, dict) and r.get("vlan"))] if isinstance(recs, list) else recs)
            for k, recs in (zone or {}).items()}
