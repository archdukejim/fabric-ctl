from ensure_sudo_rule import MARK as DEFAULT_MARK
from host_groups import rule_hosts, site_rules, text


def list_sudo_rules(samdb, lp, site):
    """Purpose: the sudo rules in the site's OU=sudoers (manual 1.6.11.7), each with who made it: fabric's editor
             (`fabric`, may be removed with it), the site's default rule (`default`, 1.6.11.3, kept by fabric) or
             anyone else (`other`: an admin's own, shown read-only).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str.
    Returns: list of {"name", "kind", "users", "commands", "run_as", "hosts" (sudoHost values), "host_group" (the
             editor's host group, "ALL", or "" for a rule not the editor's)}, by name.
    Fails:   LookupError (no such site); ldb.LdbError from the search.
    Feeds:   directory_ops (op "list_sudo_rules")."""
    out = []
    for rule in site_rules(samdb, site):
        description = text(rule, "description")
        hosts = rule_hosts(description)
        kind = "default" if description == DEFAULT_MARK else "fabric" if hosts is not None else "other"
        values = lambda attr: [str(x) for x in rule.get(attr, [])]    # noqa: E731
        out.append({"name": text(rule, "cn"), "kind": kind, "users": values("sudoUser"),
                    "commands": values("sudoCommand"),
                    "run_as": values("sudoRunAsUser") or values("sudoRunAs"), "hosts": sorted(values("sudoHost")),
                    "host_group": hosts or ""})
    return out
