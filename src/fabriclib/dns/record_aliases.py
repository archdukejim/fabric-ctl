def _in_zone(canonical, origin):
    """Purpose: A CNAME's target as a name of its own zone, if it is one.
    Inputs:  canonical — the CNAME's target as stored (relative to the zone, or absolute with a trailing dot);
             origin — the zone's name.
    Returns: the target's label in the zone ("@" for the zone itself), lower case; None for a name in another zone.
    Fails:   never.
    Feeds:   record_aliases."""
    c, origin = str(canonical or "").strip().lower(), origin.rstrip(".").lower()
    if not c:
        return None
    if not c.endswith("."):
        return c                                  # relative: a name of this zone, as BIND reads the zone file
    fq = c[:-1]
    if fq == origin:
        return "@"
    return fq[:-len(origin) - 1] if fq.endswith("." + origin) else None


def record_aliases(zone, origin, record):
    """Purpose: The aliases of an A or AAAA record in its own zone: every CNAME pointing at it, chains included (a
             CNAME to a CNAME to the record), as the zone is now (decision 2.1.4.14, manual 1.4.1.9.4).
    Inputs:  zone — the zone's dict from vars ({"A": [...], "AAAA": [...], "CNAME": [{"name", "canonical"}], ...});
             origin — the zone's name; record — the A or AAAA record's name.
    Returns: sorted list of the aliases' names (the record itself not among them); [] when the zone has no A or
             AAAA record of that name. A CNAME in another zone, or whose chain leaves the zone, is not one; a chain
             that loops is cut where it repeats; wildcard names are never aliases (a certificate's challenge name is
             not theirs).
    Fails:   never.
    Feeds:   alias_grants, key_record_choices."""
    record = str(record or "").lower()
    addresses = {str(r.get("name") or "").lower() for t in ("A", "AAAA") for r in (zone or {}).get(t) or []
                 if isinstance(r, dict)}
    if record not in addresses:
        return []
    points = {}
    for r in (zone or {}).get("CNAME") or []:
        if isinstance(r, dict) and r.get("name"):
            target = _in_zone(r.get("canonical"), origin)
            if target is not None:
                points.setdefault(target, []).append(str(r["name"]).lower())
    found, todo = set(), [record]
    while todo:
        name = todo.pop()
        for alias in points.get(name, []):
            if alias != record and alias not in found and not alias.startswith("*") and alias != "@":
                found.add(alias)
                todo.append(alias)
    return sorted(found)
