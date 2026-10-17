from fabriclib.common.errors import ValidationError

MAX_DCS = 1999      # dc-1999's id range ends at 1 999 999 999: every id stays below 2 000 000 000 (2.1.6.63)


def suggested_dc_name(taken=()):
    """Purpose: the domain controller's name fabric suggests (2.1.6.61, 2.1.6.63, manual 1.6.5.26): the domain's DCs
             numbered, `dc-0001` for a new domain's first DC and the first `dc-NNNN` not taken after it (a site joining
             the domain, a DC replacing another, 2.1.6.59), up to `dc-1999`. Any valid name may be given instead.
    Inputs:  taken — iterable of names already in the domain (its DCs and computers; any case); none for a new domain.
    Returns: str, `dc-` and four digits.
    Fails:   ValidationError when `dc-0001` to `dc-1999` are all taken: the domain has the most DCs it may have.
    Feeds:   setup/ask_dc_name, setup/advanced (the DC's name item); federation/accept_join (a taken name refused,
             naming the next free one); vars.yaml.j2 makes the same default (tests/render.py checks they agree)."""
    used = {str(t).strip().lower() for t in taken}
    for n in range(1, MAX_DCS + 1):
        if f"dc-{n:04d}" not in used:
            return f"dc-{n:04d}"
    raise ValidationError(f"the domain has {MAX_DCS} DCs, dc-0001 to dc-{MAX_DCS:04d}: the most it may have "
                          "(2.1.6.63); remove one that is gone before adding another")
