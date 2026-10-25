import ldb

from host_groups import HOST_GROUP_MARK, PREFIX, member_hosts, rule_hosts, sudo_rules, text
import paths


def list_host_groups(samdb, lp, site):
    """Purpose: the domain's host groups (manual 1.6.11.7): the groups `hosts-<name>` in OU=groups (and below), their
             machines, and the sudo rules of fabric's editor that name each.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: host groups are the
             domain's).
    Returns: list of {"name" (the AD name), "short", "machines" (host names, lower case), "other_members" (members
             that are not computers, by name), "rules" (sudo rule names), "hosts", "fabric" (made by fabric's
             editor)}, by name.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "list_host_groups")."""
    rules = {}
    for rule in sudo_rules(samdb):
        hosts = rule_hosts(text(rule, "description"))
        if hosts not in (None, "ALL"):
            rules.setdefault(hosts.lower(), []).append(text(rule, "cn"))
    out = []
    for g in samdb.search(base=paths.folder_dn(samdb, "groups"), scope=ldb.SCOPE_SUBTREE,
                          expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(PREFIX)}*))",
                          attrs=["sAMAccountName", "member", "description"]):
        name = text(g, "sAMAccountName")
        machines, others = [], []
        for dn in g.get("member", []):
            found = samdb.search(base=str(dn), scope=ldb.SCOPE_BASE, attrs=["sAMAccountName", "objectCategory"])
            if not found:
                continue
            who = text(found[0], "sAMAccountName")
            if "CN=Computer," in text(found[0], "objectCategory"):
                machines.append(who.rstrip("$").lower())
            else:
                others.append(who)
        out.append({"name": name, "short": name[len(PREFIX):], "machines": sorted(machines),
                    "other_members": sorted(others), "rules": sorted(rules.get(name.lower(), [])),
                    "hosts": member_hosts(samdb, g), "fabric": text(g, "description") == HOST_GROUP_MARK})
    return sorted(out, key=lambda x: x["name"])
