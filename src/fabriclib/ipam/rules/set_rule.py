from fabriclib.common.errors import ValidationError
from fabriclib.ipam.rules.change_rules import change_rules
from fabriclib.ipam.rules.check_rule import check_rule
from fabriclib.ipam.rules.rule_number import rule_number


def set_rule(v, actor, number, source_word, service, action, to=None, site="", force=False, secrets=None,
             container="samba", source="cli", caller=None):
    """Purpose: an access rule changed where it stands, or moved with it (manual 1.10.4.48.5, 2.1.10.61): `fabricctl
             ipam rule set`, the console's Save on a rule's row, the agent's post.networks.rule.set.
    Inputs:  v — fabric vars; actor — who asks; number — the rule's number now; source_word, service, action — the
             rule as it will be (check_rule); to — its number after, None or "" to keep it; site, force, secrets,
             container, source, caller — as change_rules.
    Returns: change_rules' result.
    Fails:   ValidationError: either number out of range; what check_rule refuses; a change that changes nothing;
             what change_rules refuses (the rule already in the list, a cut-off).
    Feeds:   ipam/cli/run_plan_change (rule set), agent/post_networks."""
    def edit(rules, plan):
        n = rule_number(number, rules)
        m = n if to in (None, "") else rule_number(to, rules)
        rule = check_rule(source_word, service, action, plan)
        if rule == rules[n - 1] and m == n:
            raise ValidationError(f"nothing to change: rule {n} is already from {rule['from']} service "
                                  f"{rule['service']} {rule['action']}")
        rules.pop(n - 1)
        rules.insert(m - 1, rule)
        where = f"rule {n}" if m == n else f"rule {n}, now {m}"
        return rules, f"changed {where}: from {rule['from']} service {rule['service']} {rule['action']}"
    return change_rules(v, actor, site, "IPAM_RULE_SET", edit, force, secrets, container, source, caller)
