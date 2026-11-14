from fabriclib.ipam.rules.constants import ANY, EXTERNAL, FABRIC, HOST, SITE


def network_names(cidr, nets):
    """Purpose: the words that name one network in a rule's source (manual 1.10.4.48.1, decision 2.1.10.62).
    Inputs:  cidr — str, one of rule_networks' "all"; nets — rule_networks' result.
    Returns: set of str: "any" for every network; "fabric" for every network the domain knows; for the site's own,
             "site", its network itself (a subnet's source), "host" when it is one of the host's VLAN's networks,
             and every VLAN reference that holds it. The rest of the IPv4 space is named by "any" alone.
    Fails:   never.
    Feeds:   service_sources, check_cut_off, rule_warnings."""
    if cidr == EXTERNAL:
        return {ANY}
    names = {ANY, FABRIC}
    if cidr not in nets["site"]:
        return names                       # another site's network
    names |= {SITE, cidr} | ({HOST} if cidr in nets["host"] else set())
    return names | {ref for ref, cidrs in nets["vlans"].items() if cidr in cidrs}
