from fabriclib.common.errors import ValidationError


def pool_text(text):
    """Purpose: a 0.7 pool as typed ("first - last") split into its two addresses (checked later by check_range).
    Inputs:  text — str.
    Returns: (first, last) str.
    Fails:   ValidationError for anything but two addresses joined by a dash.
    Feeds:   add_dhcp_subnet, set_dhcp_subnet (the 0.7 commands' aliases)."""
    parts = [p.strip() for p in str(text).split("-")]
    if len(parts) != 2 or not all(parts):
        raise ValidationError(f"pool {text!r}: two addresses, e.g. 10.1.20.100 - 10.1.20.249")
    return parts[0], parts[1]
