from fabriclib.ipam.rules.constants import ANY, GUARDED, HOST
from fabriclib.ipam.rules.decide_rule import decide_rule
from fabriclib.ipam.rules.network_names import network_names


def check_cut_off(rules, nets):
    """Purpose: whether a rule list leaves the host's VLAN without SSH or the console (manual 1.10.4.48.6, decision
             2.1.10.57), and which rule does it.
    Inputs:  rules — the list as it would be; nets — rule_networks' result for the site (its "host" empty for another
             site's plan, whose host's address is not known here: then only the words host and any are judged).
    Returns: the refusal's text, or None when the host's VLAN keeps both.
    Fails:   never.
    Feeds:   change_rules."""
    names = [network_names(c, nets) for c in nets["host"]] or [{ANY, HOST}]
    for service in GUARDED:
        for these in names:
            action, n = decide_rule(rules, these, service)
            if action != "allow":
                by = f"rule {n} denies it" if n else "no rule allows it"
                return (f"this leaves the host's VLAN without {service} ({by}): the host would be reached only at its "
                        "console; add --force on the command line, as root on the host, to mean it")
    return None
