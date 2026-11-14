from fabriclib.ipam.rules.constants import ANY


def decide_rule(rules, sources, service):
    """Purpose: what a site's rules decide for one network and one service (manual 1.10.4.48.1): the first rule whose
             source names the network and whose service is that one or `any`; the implied `any deny` when none does.
    Inputs:  rules — the site's rules, in order ({"from", "service", "action"}); sources — the words that name the
             network ({"any", "host", "10", ...}); service — one service of constants.SERVICES.
    Returns: (action "allow" or "deny", the deciding rule's number from 1, or None for the implied deny).
    Fails:   never.
    Feeds:   service_sources, check_cut_off, rule_warnings."""
    for n, rule in enumerate(rules, 1):
        if rule.get("from") in sources and rule.get("service") in (service, ANY):
            return rule.get("action"), n
    return "deny", None
