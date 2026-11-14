from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.rules.check_cut_off import check_cut_off
from fabriclib.ipam.rules.effective_rules import effective_rules
from fabriclib.ipam.rules.rule_networks import rule_networks
from fabriclib.ipam.rules.rule_warnings import rule_warnings


def _text(rule):
    """Purpose: one rule as the audit log and messages write it.
    Inputs:  rule — {"from", "service", "action"}.
    Returns: str, e.g. "from 20 service dns allow".
    Fails:   never.
    Feeds:   change_rules."""
    return f"from {rule['from']} service {rule['service']} {rule['action']}"


def change_rules(v, actor, site, event, edit, force=False, secrets=None, container="samba", source="cli",
                 caller=None):
    """Purpose: one change to a site's access rules, the way add_rule, remove_rule and move_rule make it (manual
             1.10.4.48.5, 1.10.4.48.6): the site's rules now (effective_rules) changed by `edit`, checked, then the
             whole list written in place of the old one through edit_plan (the grant's networks right `plan`, the
             audit). Refused, writing nothing: an empty list, a rule twice, and a list that cuts the host's VLAN off
             SSH or the console without --force, which only root on the host gives (2.1.10.57; audited
             IPAM_RULE_FORCED).
    Inputs:  v — fabric vars; actor — who asks; site — "" this site, or another the caller's grants reach; event —
             the audit event; edit — function(rules, plan) -> (new rules, what it did as str); force — take a cut-off
             list; secrets, container, source ("cli" or "web"), caller — as edit_plan.
    Returns: edit_plan's result; result = {"rules": the list written, "was": the list before, "did": edit's text,
             "forced": bool}.
    Fails:   ValidationError: what edit refuses; the refusals above; force from the console or a signed-in person
             ("--force is taken only on the command line, as root on the host"); what edit_plan refuses.
    Feeds:   add_rule, remove_rule, move_rule."""
    if force and (source != "cli" or caller is not None):
        raise ValidationError("--force is taken only on the command line, as root on the host")
    forced = []

    def change(plan, read, org):
        was = effective_rules(plan)
        rules, did = edit([dict(r) for r in was], plan)
        if not rules:
            raise ValidationError("a site keeps one rule at least: to deny everything, add `host any deny`")
        seen = set()
        for n, r in enumerate(rules, 1):
            key = (r["from"], r["service"], r["action"])
            if key in seen:
                raise ValidationError(f"rule {n} ({_text(r)}) is already in the list")
            seen.add(key)
        own = plan["site"] == v.get("site_name")
        nets = rule_networks(v, plan) if own else {**rule_networks({}, plan), "host": []}
        cut = check_cut_off(rules, nets)
        if cut and not force:
            raise ValidationError(cut)
        if cut:
            forced.append(cut)
        changes = [{"do": "set", "what": "rules", "site": plan["site"], "fields": {"rules": rules}}]
        detail = f"{did}; rules={' | '.join(_text(r) for r in rules)}"
        result = {"rules": rules, "was": was, "did": did, "forced": bool(cut)}
        return changes, result, detail, rule_warnings(rules, nets)
    out = edit_plan(v, actor, site, event, change, secrets, container, source, caller=caller)
    if forced:
        write_audit(actor, "IPAM_RULE_FORCED", f"site={out['site']} {forced[0]}", source)
    return out
