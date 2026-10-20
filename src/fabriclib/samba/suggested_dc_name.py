from fabriclib.common.errors import ValidationError
from fabriclib.samba.dc_name_problem import dc_name_problem

MAX_DCS = 1999      # dc-1999's id range ends at 1 999 999 999: every id stays below 2 000 000 000 (2.1.6.63)


def suggested_dc_name(taken=(), hostname="", netbios=""):
    """Purpose: the domain controller's name, which fabric alone chooses (2.1.6.63, 2.1.6.65, manual 1.6.5.26): the
             domain's DCs numbered, `dc-0001` for a new domain's first DC and the lowest `dc-NNNN` not taken after it
             (a site joining the domain, a DC replacing another, 2.1.6.59), up to `dc-1999`. A number the DC could not
             have is passed over as taken: the name its host takes in the domain (2.1.6.51), the domain's NetBIOS
             name (dc_name_problem).
    Inputs:  taken — iterable of names already in the domain (its DCs and computers, and the names given to sites
             whose DCs have not joined yet; any case); none for a new domain. hostname — the name of the host the DC
             runs on ("": not checked); netbios — the domain's NetBIOS name ("": not checked).
    Returns: str, `dc-` and four digits.
    Fails:   ValidationError when `dc-0001` to `dc-1999` are all taken: the domain has the most DCs it may have.
    Feeds:   setup/name_dc (a new domain's DC); federation/accept_join (the name a joining site's DC is given);
             vars.yaml.j2 makes the same default (tests/render.py checks they agree)."""
    used = {str(t).strip().lower() for t in taken}
    for n in range(1, MAX_DCS + 1):
        name = f"dc-{n:04d}"
        if name not in used and not dc_name_problem(name, netbios, hostname):
            return name
    raise ValidationError(f"the domain has the most domain controllers it may have ({MAX_DCS} used, none can be "
                          "added; 2.1.6.63): one that is gone must be removed from the domain before another joins")
