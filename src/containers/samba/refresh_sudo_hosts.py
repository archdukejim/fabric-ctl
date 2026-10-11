import ldb

from host_groups import find_host_group, member_hosts, rule_hosts, site_rules, text


def refresh_sudo_hosts(samdb, site):
    """Purpose: each of fabric's editor-made sudo rules on a host group names that group's machines as its `sudoHost`
             values, each machine's short name and DNS name (manual 1.6.11.7: sssd matches sudoHost against the
             machine's own names, it cannot follow an AD group), so a rule follows its host group's members. A rule
             whose host group holds no machine, or no longer exists, keeps no sudoHost: it applies nowhere. Run after
             every change of a host group's members, and at each convergence (a member added with other tools).
    Inputs:  samdb — SamDB (as the site's agent, or the system at convergence); site — str.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a search or a change.
    Feeds:   set_host_group_member, add_sudo_rule, converge."""
    done = []
    for rule in site_rules(samdb, site):
        hosts = rule_hosts(text(rule, "description"))
        if hosts in (None, "ALL"):
            continue
        try:
            want = member_hosts(samdb, find_host_group(samdb, site, hosts))
        except ValueError:
            want = []
        have = sorted(str(x) for x in rule.get("sudoHost", []))
        if have == want:
            continue
        msg = ldb.Message(rule.dn)
        msg["sudoHost"] = ldb.MessageElement(want, ldb.FLAG_MOD_REPLACE, "sudoHost")
        samdb.modify(msg)
        done.append(f"sudo rule {text(rule, 'cn')}: hosts {', '.join(want) or '(none)'} (host group {hosts})")
    return done
