import ldb

from host_groups import HOST_GROUP_MARK, member_hosts, rule_hosts, site_rules, text
from paths import site_dn


def list_host_groups(samdb, lp, site):
    """Purpose: the site's host groups (manual 1.6.11.7): the groups `<site>-hosts-<name>` in its OU=groups, their
             machines, and the sudo rules of fabric's editor that name each.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str.
    Returns: list of {"name" (the AD name), "short", "machines" (host names, lower case), "other_members" (members
             that are not computers, by name), "rules" (sudo rule names), "fabric" (made by fabric's editor)}, by name.
    Fails:   LookupError (no such site); ldb.LdbError from a search.
    Feeds:   directory_ops (op "list_host_groups")."""
    prefix = f"{site}-hosts-"
    rules = {}
    for rule in site_rules(samdb, site):
        hosts = rule_hosts(text(rule, "description"))
        if hosts not in (None, "ALL"):
            rules.setdefault(hosts.lower(), []).append(text(rule, "cn"))
    out = []
    for g in samdb.search(base=f"OU=groups,{site_dn(samdb, site)}", scope=ldb.SCOPE_ONELEVEL,
                          expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(prefix)}*))",
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
        out.append({"name": name, "short": name[len(prefix):], "machines": sorted(machines),
                    "other_members": sorted(others), "rules": sorted(rules.get(name.lower(), [])),
                    "hosts": member_hosts(samdb, g), "fabric": text(g, "description") == HOST_GROUP_MARK})
    return sorted(out, key=lambda x: x["name"])
