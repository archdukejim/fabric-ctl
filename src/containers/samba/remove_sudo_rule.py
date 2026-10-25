from host_groups import grant_rule_where, rule_hosts, sudo_rules, text


def remove_sudo_rule(samdb, lp, site, name):
    """Purpose: one of fabric's editor-made sudo rules deleted from the domain's OU=sudoers (manual 1.6.11.7). The rules
             admins made with their own tools are never removed here.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the rule's name.
    Returns: {"name"}.
    Fails:   ValueError "no sudo rule …", "… was not made by fabric's sudo editor …"; ldb.LdbError
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_sudo_rule")."""
    rule = next((r for r in sudo_rules(samdb) if text(r, "cn").lower() == name.lower()), None)
    if rule is None:
        raise ValueError(f"no sudo rule {name}")
    if grant_rule_where(text(rule, "description")) is not None:
        raise ValueError(f"{name} is a grant's sudo rule (manual 1.6.13.4): change the grant (fabricctl domain grant)")
    if rule_hosts(text(rule, "description")) is None:
        raise ValueError(f"{name} was not made by fabric's sudo editor: it is an admin's own, changed with their "
                         "own tools")
    samdb.delete(str(rule.dn))
    return {"name": text(rule, "cn")}
