from fabriclib.ipam.rules.change_rules import change_rules
from fabriclib.ipam.rules.rule_number import rule_number


def remove_rule(v, actor, number, site="", force=False, secrets=None, container="samba", source="cli", caller=None):
    """Purpose: an access rule removed from a site's list by its number (manual 1.10.4.48.5): `fabricctl ipam rule
             remove`, the console's Remove, the agent's post.networks.rule.remove.
    Inputs:  v — fabric vars; actor — who asks; number — the rule's number; site, force, secrets, container, source,
             caller — as change_rules.
    Returns: change_rules' result.
    Fails:   ValidationError: what rule_number refuses; what change_rules refuses (the last rule, a cut-off).
    Feeds:   ipam/cli/run_plan_change (rule remove), agent/post_networks."""
    def edit(rules, plan):
        n = rule_number(number, rules)
        gone = rules.pop(n - 1)
        return rules, f"removed rule {n}: from {gone['from']} service {gone['service']} {gone['action']}"
    return change_rules(v, actor, site, "IPAM_RULE_REMOVE", edit, force, secrets, container, source, caller)
