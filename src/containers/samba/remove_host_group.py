from host_groups import find_host_group, host_group_name, rule_hosts, sudo_rules, text


def remove_host_group(samdb, lp, site, name):
    """Purpose: a host group deleted (manual 1.6.11.7); refused while one of fabric's sudo rules names it, so no rule
             is left aimed at a group that is gone. Its machines stay as they are.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the short name.
    Returns: {"name": the AD name}.
    Fails:   ValueError "no host group …", "host group … is named by sudo rule(s) …: remove them first";
             ldb.LdbError ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "remove_host_group")."""
    full = host_group_name(name)
    group = find_host_group(samdb, full)
    users = [text(r, "cn") for r in sudo_rules(samdb)
             if (rule_hosts(text(r, "description")) or "").lower() == full.lower()]
    if users:
        raise ValueError(f"host group {full} is named by sudo rule(s) {', '.join(users)}: remove them first")
    samdb.delete(str(group.dn))
    return {"name": full}
