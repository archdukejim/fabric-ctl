from fabriclib.common.errors import ValidationError


def check_block(number, sites, site):
    """Purpose: a site's number checked (manual 1.10.4.13.4, 2.1.10.12, 2.1.10.16): a whole number from 1 to 255 (the
             second octet of the suggested `10.<site>.<VLAN>.0/24`), no other site's in the organisation.
    Inputs:  number — int or str as typed; sites — read_plan's "sites" [{"name", "created", "block"}]; site — the
             site being numbered.
    Returns: int.
    Fails:   ValidationError: not a whole number from 1 to 255; a number another site has (naming it).
    Feeds:   set_block, setup/ask_site_number."""
    text = str(number).strip()
    if isinstance(number, bool) or not text.isdigit() or not 1 <= int(text) <= 255:
        raise ValidationError(f"site number {number!r}: a whole number from 1 to 255 (the second octet of "
                              "10.<site>.<VLAN>.0/24)")
    n = int(text)
    other = next((s["name"] for s in sites if s.get("block") == n and s["name"] != site), None)
    if other:
        raise ValidationError(f"site number {n} is already {other}'s: each site's number is unique in the "
                              "organisation")
    return n
