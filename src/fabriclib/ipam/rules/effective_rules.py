from fabriclib.ipam.rules.seed_rules import seed_rules


def effective_rules(plan):
    """Purpose: the rules a site is enforced by now (manual 1.10.4.48.4): the ones kept on its record, or, while none
             are kept, the ones it would be given (seed_rules), so an upgraded site keeps what it reached before its
             rules are written.
    Inputs:  plan — the site's plan (site_plan's: rules, rules_kept, vlans, subnets), or None.
    Returns: list of rules, in order.
    Fails:   never.
    Feeds:   service_sources, ipam/rules/show_rules, ipam/rules/change_rules."""
    plan = plan or {}
    if plan.get("rules_kept") and plan.get("rules"):
        return [dict(r) for r in plan["rules"]]
    return seed_rules(plan)
