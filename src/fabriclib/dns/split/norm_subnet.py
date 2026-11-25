import ipaddress


def norm_subnet(text):
    """Purpose: a subnet written as its network (10.77.0.0/24), or "" when it is not one.
    Inputs:  text — str or None.
    Returns: str.
    Fails:   never.
    Feeds:   offered_subnets, split_checks (pick_networks)."""
    try:
        return str(ipaddress.ip_network(str(text or "").strip(), strict=False)) if text else ""
    except ValueError:
        return ""
