import ldb

from host_groups import find_host_group, rule_description
import paths
from refresh_sudo_hosts import refresh_sudo_hosts

# the sudoUser values that mean every person: ALL, AD's Domain Users (fabric's `users`), and any site's group
# (`%site-<name>`, a site's people)
EVERYONE = {"all", "%domain users", "%users"}


def _everyone(who):
    """Purpose: whether a sudoUser value means every person, or every person of a site.
    Inputs:  who — str.
    Returns: bool.
    Fails:   never.
    Feeds:   add_sudo_rule."""
    return who.lower() in EVERYONE or who.lower().startswith("%site-")


def _exists(samdb, who):
    """Purpose: whether a sudoUser value names something in the domain: a person (`alice`) or a group (`%group`).
    Inputs:  samdb — SamDB; who — str (not ALL).
    Returns: bool.
    Fails:   ldb.LdbError from the search.
    Feeds:   add_sudo_rule."""
    group = who.startswith("%")
    name = who[1:] if group else who
    kind = "(objectClass=group)" if group else "(objectCategory=person)"
    return bool(samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                             expression=f"(&{kind}(sAMAccountName={ldb.binary_encode(name)}))"))


def add_sudo_rule(samdb, lp, site, name, users, commands, run_as, hosts):
    """Purpose: a sudo rule of fabric's editor (manual 1.6.11.7): a `sudoRole` `CN=<name>` in the domain's OU=sudoers
             (every joined machine reads it, 1.6.7.4; never a fabric host, 1.6.13.6), marked as the editor's in its
             description with where it applies; on a host group its sudoHost values are that group's machines
             (refresh_sudo_hosts). Refused: a rule granting ALL commands to everyone (or a whole site's people),
             someone or a group not in the domain, a host group the domain does not have. Names and values are
             checked by fabric first.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: sudo rules are the
             domain's); name — the rule's name; users — list of sudoUser values (`alice`, `%group`, `ALL`); commands —
             list (absolute paths, or `ALL`); run_as — list of sudoRunAsUser values (the machine's own accounts, such
             as root: not looked up); hosts — "ALL" (every joined machine) or a host group's AD name.
    Returns: {"name", "hosts": the sudoHost values written}.
    Fails:   ValueError "a rule granting ALL commands to everyone is refused …", "no person or group … in the
             domain", "no host group …"; ldb.LdbError ERR_ENTRY_ALREADY_EXISTS (a rule of that name),
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "add_sudo_rule")."""
    if "ALL" in commands and any(_everyone(u) for u in users):
        raise ValueError("a rule granting ALL commands to everyone is refused (manual 1.6.11.7): name the people or "
                         "groups who need it, or the commands they need")
    missing = [u for u in users if u != "ALL" and not _exists(samdb, u)]    # run-as: local accounts (root)
    if missing:
        raise ValueError(f"no person or group {', '.join(missing)} in the domain")
    if hosts != "ALL":
        find_host_group(samdb, hosts)
    dn = f"CN={name},{paths.folder_dn(samdb, 'sudoers')}"
    entry = {"dn": dn, "objectClass": "sudoRole", "sudoUser": list(users), "sudoCommand": list(commands),
             "sudoRunAsUser": list(run_as), "description": [rule_description(hosts)]}
    if hosts == "ALL":
        entry["sudoHost"] = ["ALL"]
    samdb.add(entry)
    refresh_sudo_hosts(samdb)
    rule = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["sudoHost"])[0]
    return {"name": name, "hosts": sorted(str(x) for x in rule.get("sudoHost", []))}
