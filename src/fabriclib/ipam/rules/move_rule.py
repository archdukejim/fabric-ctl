from fabriclib.common.errors import ValidationError
from fabriclib.ipam.rules.change_rules import change_rules
from fabriclib.ipam.rules.rule_number import rule_number


def move_rule(v, actor, number, to, site="", force=False, secrets=None, container="samba", source="cli",
              caller=None):
    """Purpose: an access rule moved to another number in a site's list (manual 1.10.4.48.5): `fabricctl ipam rule
             move`, the console's Move up and Move down, the agent's post.networks.rule.move.
    Inputs:  v — fabric vars; actor — who asks; number — the rule's number now; to — its number after; site, force,
             secrets, container, source, caller — as change_rules.
    Returns: change_rules' result.
    Fails:   ValidationError: either number out of range; the same number twice (nothing to change); what
             change_rules refuses.
    Feeds:   ipam/cli/run_plan_change (rule move), agent/post_networks."""
    def edit(rules, plan):
        n, m = rule_number(number, rules), rule_number(to, rules)
        if n == m:
            raise ValidationError(f"nothing to change: rule {n} is already number {m}")
        rules.insert(m - 1, rules.pop(n - 1))
        return rules, f"moved rule {n} to {m}"
    return change_rules(v, actor, site, "IPAM_RULE_MOVE", edit, force, secrets, container, source, caller)
