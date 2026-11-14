from fabriclib.ipam.rules.constants import ANY, HOST


def network_names(cidr, nets):
    """Purpose: the words that name one network in a rule's source (manual 1.10.4.48.1).
    Inputs:  cidr — str; nets — rule_networks' result.
    Returns: set of str: "any", "host" when it is one of the host's VLAN's networks, and every VLAN reference that
             holds it.
    Fails:   never.
    Feeds:   service_sources, check_cut_off, rule_warnings."""
    names = {ANY} | ({HOST} if cidr in nets["host"] else set())
    return names | {ref for ref, cidrs in nets["vlans"].items() if cidr in cidrs}
