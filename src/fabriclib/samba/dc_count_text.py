from fabriclib.samba.suggested_dc_name import MAX_DCS


def dc_count_text(used):
    """Purpose: the domain's domain controllers as a person reads them during setup or a join: how many the domain uses
             and how many can still be added, never a DC's name or fabric's naming scheme (2.1.6.65, revised
             2026-10-18: "1 dc used, 1998 dcs can be added").
    Inputs:  used — int, the DCs the domain has (with the one being made).
    Returns: str, e.g. "1 DC used, 1998 can be added".
    Fails:   never for an int.
    Feeds:   setup/choose_plan (a new domain), setup/join_federation (a site join, the count after it)."""
    used = int(used)
    return f"{used} DC{'s' if used != 1 else ''} used, {max(MAX_DCS - used, 0)} can be added"
