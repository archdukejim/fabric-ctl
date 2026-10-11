import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.directory.create_host_group import create_host_group
from fabriclib.directory.list_host_groups import list_host_groups
from fabriclib.directory.remove_host_group import remove_host_group
from fabriclib.directory.set_host_group_member import set_host_group_member

USAGE = """usage: fabricctl machines groups                     the site's host groups, their machines, their sudo rules
       fabricctl machines group create <group>    a new host group, <site>-hosts-<group>
       fabricctl machines group delete <group>    remove it (refused while a sudo rule names it)
       fabricctl machines group add <group> <machine>
       fabricctl machines group remove <group> <machine>
                                                  put one of the site's machines in a host group, or take it out
  A host group is an AD group of machines (manual 4.6.6): sudo rules name it (fabricctl sudo), and a log-on policy
  may name it like any group. <group> is its short name (web) or its AD name (<site>-hosts-web)."""


def _show(groups):
    """Purpose: print the host groups.
    Inputs:  groups — list_host_groups' list.
    Returns: None.
    Fails:   never.
    Feeds:   run_machines_command."""
    if not groups:
        print("no host groups yet: fabricctl machines group create <group>")
    for g in groups:
        print(f"{g['name']}: {', '.join(g['machines']) or '(no machines)'}"
              + (f"; also {', '.join(g['other_members'])}" if g["other_members"] else "")
              + (f"; sudo rules: {', '.join(g['rules'])}" if g["rules"] else "")
              + ("" if g["fabric"] else " (not made by fabric)"))


def run_machines_command(v, args):
    """Purpose: `fabricctl machines …` (manual 4.6.6): only routes to the host group functions, as root (the audit
             names the CLI).
    Inputs:  v — rendered vars; args — list of str after `machines`.
    Returns: exit status: 0 ok, 1 a refused change, 2 usage.
    Fails:   OSError from the audit log; OpenBao sealed (load_secrets) propagate.
    Feeds:   cli.main."""
    actor = getpass.getuser()
    try:
        if args == ["groups"]:
            _show(list_host_groups(v))
            return 0
        op, rest = (args[1] if len(args) > 1 else ""), args[2:]
        if args[:1] == ["group"] and op in ("create", "delete") and len(rest) == 1:
            done = (create_host_group if op == "create" else remove_host_group)(v, actor, rest[0])
            print(f"host group {done['name']} {'created' if op == 'create' else 'removed'}")
            return 0
        if args[:1] == ["group"] and op in ("add", "remove") and len(rest) == 2:
            done = set_host_group_member(v, actor, rest[0], rest[1], op == "add")
            print(f"{done['machine']}: {'in' if done['member'] else 'out of'} {done['group']}"
                  + ("" if done["changed"] else " (already)"))
            for line in done["rules"]:
                print(f"  {line}")
            return 0
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
