from host_groups import rule_hosts, sudo_rules, text


def list_sudo_rules(samdb, lp, site):
    """Purpose: the sudo rules in the domain's OU=sudoers (manual 1.6.11.7), each with who made it: fabric's editor
             (`fabric`, may be removed with it) or anyone else (`other`: an admin's own, shown read-only).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: the domain's rules).
    Returns: list of {"name", "kind", "users", "commands", "run_as", "hosts" (sudoHost values), "host_group" (the
             editor's host group, "ALL", or "" for a rule not the editor's)}, by name.
    Fails:   ldb.LdbError from the search.
    Feeds:   directory_ops (op "list_sudo_rules")."""
    out = []
    for rule in sudo_rules(samdb):
        hosts = rule_hosts(text(rule, "description"))
        values = lambda attr: [str(x) for x in rule.get(attr, [])]    # noqa: E731
        out.append({"name": text(rule, "cn"), "kind": "fabric" if hosts is not None else "other",
                    "users": values("sudoUser"), "commands": values("sudoCommand"),
                    "run_as": values("sudoRunAsUser") or values("sudoRunAs"), "hosts": sorted(values("sudoHost")),
                    "host_group": hosts or ""})
    return out
