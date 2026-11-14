from fabriclib.common.errors import ValidationError
from fabriclib.ipam.rules.change_rules import change_rules
from fabriclib.ipam.rules.check_rule import check_rule


def add_rule(v, actor, source_word, service, action, at=None, site="", force=False, secrets=None,
             container="samba", source="cli", caller=None):
    """Purpose: an access rule added to a site's list (manual 1.10.4.48.5): `fabricctl ipam rule add`, the console's
             Add, the agent's post.networks.rule.add.
    Inputs:  v — fabric vars; actor — who asks; source_word — the rule's source (host, any, a VLAN); service, action —
             as check_rule; at — its number in the list (1 first), None or "" for last; site, force, secrets,
             container, source, caller — as change_rules.
    Returns: change_rules' result.
    Fails:   ValidationError: what check_rule refuses; a position that is not a number from 1 to one past the last;
             what change_rules refuses.
    Feeds:   ipam/cli/run_plan_change (rule add), agent/post_networks."""
    def edit(rules, plan):
        rule = check_rule(source_word, service, action, plan)
        if at in (None, ""):
            pos = len(rules) + 1
        else:
            try:
                pos = int(at)
            except ValueError:
                raise ValidationError(f"--at {at!r}: a rule's number, 1 to {len(rules) + 1}")
            if not 1 <= pos <= len(rules) + 1:
                raise ValidationError(f"--at {at}: a rule's number, 1 to {len(rules) + 1}")
        rules.insert(pos - 1, rule)
        return rules, f"added as rule {pos}: from {rule['from']} service {rule['service']} {rule['action']}"
    return change_rules(v, actor, site, "IPAM_RULE_ADD", edit, force, secrets, container, source, caller)
