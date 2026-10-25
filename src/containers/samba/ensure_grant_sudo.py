import ldb

from grant_names import who_group, where_group
from host_groups import grant_rule_description, grant_rule_where, sudo_rules, text
import paths
from refresh_sudo_hosts import refresh_sudo_hosts

RUN_AS = ["root"]


def rule_name(grant):
    """Purpose: a grant's sudo rule's name.
    Inputs:  grant — str, the grant's name.
    Returns: str "grant-<name>".
    Fails:   never.
    Feeds:   ensure_grant_sudo, show_grant."""
    return f"grant-{grant}"


def ensure_grant_sudo(samdb, grants):
    """Purpose: one `sudoRole` per allowing grant with sudo (manual 1.6.13.4), `CN=grant-<name>` in the domain's
             OU=sudoers: `sudoUser: %grant-<name>-who`, the grant's commands (ALL, or its list) as root, its
             `sudoHost`s its computed where group's machines (refresh_sudo_hosts). A grant's rule no longer wanted is
             deleted; a rule of that name that is not a grant's (an admin's own) is left as it is, and said.
    Inputs:  samdb — SamDB (as the system); grants — read_grants' list.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from AD.
    Feeds:   compile_grants."""
    done = []
    want = {rule_name(g["name"]): g for g in grants if g["kind"] == "allow" and g["sudo"]}
    have = {text(r, "cn"): r for r in sudo_rules(samdb)}
    for name, rule in have.items():
        if grant_rule_where(text(rule, "description")) is not None and name not in want:
            samdb.delete(str(rule.dn))
            done.append(f"sudo rule {name} removed (its grant has no sudo now)")
    for name, g in sorted(want.items()):
        entry = {"sudoUser": [f"%{who_group(g['name'])}"], "sudoCommand": list(g["sudo"]),
                 "sudoRunAsUser": RUN_AS, "description": [grant_rule_description(where_group(g["name"]))]}
        rule = have.get(name)
        if rule is None:
            samdb.add({"dn": f"CN={name},{paths.folder_dn(samdb, 'sudoers')}", "objectClass": "sudoRole", **entry})
            done.append(f"sudo rule {name} added")
            continue
        if grant_rule_where(text(rule, "description")) is None:
            done.append(f"sudo rule {name} is not a grant's (an admin's own): left as it is; grant {g['name']} "
                        "gives no sudo until it is renamed")
            continue
        msg = ldb.Message(rule.dn)
        for attr, values in entry.items():
            if sorted(str(x) for x in rule.get(attr, [])) != sorted(values):
                msg[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)
        if len(msg) > 0:
            samdb.modify(msg)
            done.append(f"sudo rule {name} changed")
    return done + refresh_sudo_hosts(samdb)
