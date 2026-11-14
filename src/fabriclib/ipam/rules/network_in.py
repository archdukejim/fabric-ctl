import ipaddress


def network_in(cidr, cidrs):
    """Purpose: whether a network lies wholly inside one of a list of networks (manual 1.10.4.48.1): how a service's
             allow list is read once `any` has made it 0.0.0.0/0 less the denied networks (decision 2.1.10.62).
    Inputs:  cidr — str; cidrs — list of str.
    Returns: bool (False for a network that does not parse; a list entry that does not parse is skipped).
    Fails:   never.
    Feeds:   access_denied, dhcp_allowed."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    for other in cidrs:
        try:
            big = ipaddress.ip_network(other, strict=False)
        except ValueError:
            continue
        if net.version == big.version and net.subnet_of(big):
            return True
    return False
