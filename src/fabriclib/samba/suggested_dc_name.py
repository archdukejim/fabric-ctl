def suggested_dc_name(taken=()):
    """Purpose: the domain controller's name fabric suggests (2.1.6.61, manual 1.6.5.23): the domain's DCs numbered,
             `dc-001` for a new domain's first DC and the first `dc-NNN` not taken after it (a site joining the domain,
             a DC replacing another, 2.1.6.59). Any valid name may be given instead.
    Inputs:  taken — iterable of names already in the domain (its DCs and computers; any case); none for a new domain.
    Returns: str, `dc-` and three digits (more past 999).
    Fails:   never.
    Feeds:   setup/ask_dc_name, setup/advanced (the DC's name item); federation/accept_join (a taken name refused,
             naming the next free one); vars.yaml.j2 makes the same default (tests/render.py checks they agree)."""
    used = {str(t).strip().lower() for t in taken}
    n = 1
    while f"dc-{n:03d}" in used:
        n += 1
    return f"dc-{n:03d}"
