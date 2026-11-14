from fabriclib.ipam.rules.constants import ANY, FABRIC, HOST, SITE


def source_networks(word, nets):
    """Purpose: what a rule's source stands for, as the listing and the console show it beside the source (manual
             1.10.4.48.5, decision 2.1.10.62).
    Inputs:  word — the rule's "from"; nets — rule_networks' result.
    Returns: str: the networks of host, a VLAN or the site, joined ("10.1.10.0/24, 10.1.11.0/24"); "every site's
             networks (n)" for fabric; "every address, outside ones too" for any; "" for a subnet (its own name
             says it) or a source with no network yet.
    Fails:   never.
    Feeds:   show_rules, rules_view."""
    if word == ANY:
        return "every address, outside ones too"
    if word == FABRIC:
        return f"every site's networks ({len(nets['fabric'])})"
    if word == HOST:
        return ", ".join(nets["host"])
    if word == SITE:
        return ", ".join(nets["site"])
    return ", ".join(nets["vlans"].get(word, []))
