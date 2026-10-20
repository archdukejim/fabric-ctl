"""Host groups and fabric's sudo rules (manual 1.6.11.7, 1.6.13.3): their names, the marks fabric writes on them, and
the lookups the operations on them share. Both are the domain's: host groups in OU=groups, sudo rules in OU=sudoers
(2.1.6.80)."""
import ldb

import paths

HOST_GROUP_MARK = "fabric: a host group (manual 1.6.11.7)"
RULE_MARK = "fabric: a sudo rule of fabric's editor (manual 1.6.11.7)"     # fabric's editor-made sudo rules
GRANT_RULE_MARK = "fabric: a grant's sudo rule (manual 1.6.13.4)"           # the grants' sudo rules
HOSTS = "; hosts: "
PREFIX = "hosts-"                   # a host group's AD name: hosts-<name> (1.6.13.3: no site prefix)


def host_group_name(name):
    """Purpose: a host group's AD name from its short name.
    Inputs:  name — the short name (`web`).
    Returns: str "hosts-<name>".
    Fails:   never.
    Feeds:   create_host_group, remove_host_group, set_host_group_member."""
    return f"{PREFIX}{name}"


def find_host_group(samdb, name):
    """Purpose: one of the domain's host groups, in OU=groups (and the OUs an admin made below it).
    Inputs:  samdb — SamDB; name — the group's AD name (`hosts-<name>`).
    Returns: ldb.Message (dn, member).
    Fails:   ValueError "no host group <name>"; ldb.LdbError from the search.
    Feeds:   remove_host_group, set_host_group_member, add_sudo_rule, refresh_sudo_hosts."""
    found = samdb.search(base=paths.folder_dn(samdb, "groups"), scope=ldb.SCOPE_SUBTREE, attrs=["member"],
                         expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))")
    if not found or not name.startswith(PREFIX):
        raise ValueError(f"no host group {name}")
    return found[0]


def member_hosts(samdb, group):
    """Purpose: the host names sudo matches for a host group's machines: each member computer's short name and its
             DNS name, lower case (sssd asks the DC for the rules naming this host's short name or FQDN).
    Inputs:  samdb — SamDB; group — ldb.Message of the group (with member).
    Returns: sorted list of str (empty when the group holds no computer).
    Fails:   ldb.LdbError from a search.
    Feeds:   refresh_sudo_hosts, list_host_groups."""
    names = set()
    for dn in group.get("member", []):
        found = samdb.search(base=str(dn), scope=ldb.SCOPE_BASE, expression="(objectCategory=computer)",
                             attrs=["sAMAccountName", "dNSHostName"])
        for m in found:
            names.add(str(m["sAMAccountName"][0]).rstrip("$").lower())
            if m.get("dNSHostName"):
                names.add(str(m["dNSHostName"][0]).lower())
    return sorted(names)


def rule_description(hosts):
    """Purpose: the description fabric writes on one of its editor's sudo rules: the mark, and where it applies.
    Inputs:  hosts — "ALL" or a host group's AD name.
    Returns: str.
    Fails:   never.
    Feeds:   add_sudo_rule."""
    return f"{RULE_MARK}{HOSTS}{hosts}"


def rule_hosts(description):
    """Purpose: where one of fabric's editor-made rules applies, from its description.
    Inputs:  description — str.
    Returns: "ALL", a host group's AD name, or None when the rule is not the editor's.
    Fails:   never.
    Feeds:   list_sudo_rules, remove_sudo_rule, remove_host_group, refresh_sudo_hosts."""
    if not description.startswith(RULE_MARK + HOSTS):
        return None
    return description[len(RULE_MARK + HOSTS):]


def sudo_rules(samdb):
    """Purpose: the sudo rules in the domain's OU=sudoers.
    Inputs:  samdb — SamDB.
    Returns: list of ldb.Message (cn, sudoUser, sudoHost, sudoCommand, sudoRunAsUser, description), by name.
    Fails:   ldb.LdbError from the search (OU=sudoers missing: the domain has not converged).
    Feeds:   list_sudo_rules, remove_sudo_rule, remove_host_group, refresh_sudo_hosts, list_host_groups."""
    found = samdb.search(base=paths.folder_dn(samdb, "sudoers"), scope=ldb.SCOPE_ONELEVEL,
                         expression="(objectClass=sudoRole)",
                         attrs=["cn", "sudoUser", "sudoHost", "sudoCommand", "sudoRunAsUser", "sudoRunAs",
                                "description"])
    return sorted(found, key=lambda m: str(m["cn"][0]).lower())


def text(msg, attr):
    """Purpose: an attribute's first value as text.
    Inputs:  msg — ldb.Message; attr — str.
    Returns: str ("" when absent).
    Fails:   never.
    Feeds:   the host group and sudo rule operations."""
    return str(msg[attr][0]) if msg.get(attr) else ""


def grant_rule_description(where):
    """Purpose: the description fabric writes on a grant's sudo rule (manual 1.6.13.4): the mark, and the computed
             group whose machines it applies to.
    Inputs:  where — the grant's computed where group (`grant-<name>-where`).
    Returns: str.
    Fails:   never.
    Feeds:   ensure_grant_sudo."""
    return f"{GRANT_RULE_MARK}{HOSTS}{where}"


def grant_rule_where(description):
    """Purpose: the computed group a grant's sudo rule applies to, from its description.
    Inputs:  description — str.
    Returns: the group's name (`grant-<name>-where`), or None when the rule is not a grant's.
    Fails:   never.
    Feeds:   refresh_sudo_hosts, ensure_grant_sudo, list_sudo_rules, remove_sudo_rule."""
    if not description.startswith(GRANT_RULE_MARK + HOSTS):
        return None
    return description[len(GRANT_RULE_MARK + HOSTS):]
