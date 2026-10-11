from ensure_sudo_rule import MARK as DEFAULT_MARK
from host_groups import rule_hosts, site_rules, text


def remove_sudo_rule(samdb, lp, site, name):
    """Purpose: one of fabric's editor-made sudo rules deleted from the site's OU=sudoers (manual 1.6.11.7). The site's
             default rule (1.6.11.3) and the rules admins made with their own tools are never removed here.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the rule's name.
    Returns: {"name"}.
    Fails:   ValueError "no sudo rule …", "… is the site's default rule …", "… was not made by fabric's sudo editor
             …"; ldb.LdbError ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_sudo_rule")."""
    rule = next((r for r in site_rules(samdb, site) if text(r, "cn").lower() == name.lower()), None)
    if rule is None:
        raise ValueError(f"no sudo rule {name} in site {site}")
    description = text(rule, "description")
    if description == DEFAULT_MARK:
        raise ValueError(f"{name} is the site's default rule (its fabric-admins, manual 1.6.11.3): fabric keeps it")
    if rule_hosts(description) is None:
        raise ValueError(f"{name} was not made by fabric's sudo editor: it is an admin's own, changed with their "
                         "own tools")
    samdb.delete(str(rule.dn))
    return {"name": text(rule, "cn")}
