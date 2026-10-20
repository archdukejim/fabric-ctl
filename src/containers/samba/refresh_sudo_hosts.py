import ldb

from host_groups import find_host_group, grant_rule_where, member_hosts, rule_hosts, sudo_rules, text
import paths


def _computed_group(samdb, name):
    """Purpose: one of the grants' computed groups, in OU=fabric,OU=groups.
    Inputs:  samdb — SamDB; name — its sAMAccountName (`grant-<name>-where`).
    Returns: ldb.Message (dn, member).
    Fails:   ValueError when there is none; ldb.LdbError from the search.
    Feeds:   refresh_sudo_hosts."""
    found = samdb.search(base=paths.computed_groups_dn(samdb), scope=ldb.SCOPE_ONELEVEL, attrs=["member"],
                         expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))")
    if not found:
        raise ValueError(f"no computed group {name}")
    return found[0]


def refresh_sudo_hosts(samdb):
    """Purpose: each of fabric's sudo rules on a group of machines names that group's machines as its `sudoHost`
             values, each machine's short name and DNS name (sssd matches sudoHost against the machine's own names, it
             cannot follow an AD group): an editor-made rule its host group's (manual 1.6.11.7), a grant's rule its
             computed where group's (1.6.13.4). So a rule follows its group's members. A rule whose group holds no
             machine, or no longer exists, keeps no sudoHost: it applies nowhere. Run after every change of a host
             group's members, at every compile of the grants and at each convergence (a member added with other
             tools).
    Inputs:  samdb — SamDB (as the DC's agent, or the system at convergence and compile).
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a search or a change.
    Feeds:   set_host_group_member, add_sudo_rule, converge, ensure_grant_sudo."""
    done = []
    for rule in sudo_rules(samdb):
        description = text(rule, "description")
        hosts, where = rule_hosts(description), grant_rule_where(description)
        if where is None and hosts in (None, "ALL"):
            continue
        try:
            group = _computed_group(samdb, where) if where else find_host_group(samdb, hosts)
            want = member_hosts(samdb, group)
        except ValueError:
            want = []
        have = sorted(str(x) for x in rule.get("sudoHost", []))
        if have == want:
            continue
        msg = ldb.Message(rule.dn)
        msg["sudoHost"] = ldb.MessageElement(want, ldb.FLAG_MOD_REPLACE, "sudoHost")
        samdb.modify(msg)
        done.append(f"sudo rule {text(rule, 'cn')}: hosts {', '.join(want) or '(none)'} "
                    f"({'grant group' if where else 'host group'} {where or hosts})")
    return done
