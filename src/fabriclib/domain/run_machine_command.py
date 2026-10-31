import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.domain.keytab_command import keytab_command
from fabriclib.domain.move_machine import move_machine
from fabriclib.domain.read_options import read_options
from fabriclib.domain.set_machine_site import set_machine_site
from fabriclib.domain.set_machine_type import set_machine_type

USAGE = """usage: fabricctl domain machine move <name> <folder>       to any folder under machines (e.g. servers/web);
                                                         nobody's access changes
       fabricctl domain machine type <name> server|desktop|network [--move]   its type group (and its type's folder)
       fabricctl domain machine sites <name> add|remove <site>
       fabricctl domain machine keytab <name> --service <class> --user <user> [--path <file>]
                                                         the command its administrator runs on it over SSH
  As root, acting for the Enterprise Admin (manual 1.6.12.6, 1.6.12.9)."""


def run_machine_command(v, args):
    """Purpose: `fabricctl domain machine …` (manual 4.6.11): only parses and routes to the computer functions, as
             root (caller None).
    Inputs:  v — rendered vars; args — list of str after `machine`.
    Returns: exit status: 0 done, 1 refused (with why), 2 usage.
    Fails:   OSError from the audit log; OpenBao sealed (load_secrets) propagate.
    Feeds:   samba/run_domain_command."""
    if len(args) < 2 or args[0] not in ("move", "type", "sites", "keytab") or args[1].startswith("-"):
        print(USAGE)
        return 2
    cmd, name, rest, actor = args[0], args[1], args[2:], getpass.getuser()
    try:
        if cmd == "move" and len(rest) == 1:
            done = move_machine(v, actor, name, rest[0], source="cli")
            print(f"{name}: {'moved to' if done['changed'] else 'already in'} {done['path']}")
            return 0
        if cmd == "type" and rest and rest[1:] in ([], ["--move"]):
            done = set_machine_type(v, actor, name, rest[0], rest[1:] == ["--move"], source="cli")
            print(f"{name}: a {rest[0]}; " + ("; ".join(done["changed"]) or "nothing changed")
                  + (f" (kept in its folder {done['kept_folder']})" if done["kept_folder"] else ""))
            return 0
        if cmd == "sites" and len(rest) == 2 and rest[0] in ("add", "remove"):
            done = set_machine_site(v, actor, name, rest[1], rest[0] == "add", source="cli")
            print(f"{name}: {'in' if done['member'] else 'out of'} site {rest[1]}"
                  + ("" if done["changed"] else " (already)"))
            return 0
        if cmd == "keytab":
            o = read_options(rest, ("--service", "--user", "--path"))
            done = keytab_command(v, name, o.get("--service", ""), o.get("--user", ""), o.get("--path", ""))
            print(f"on {done['machine']}, its administrator runs (over SSH; nothing secret in it):\n"
                  f"  {done['command']}")
            print(f"it adds {' and '.join(done['spns'])} to {done['machine'].upper()}$ and writes the keytab")
            return 0
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
