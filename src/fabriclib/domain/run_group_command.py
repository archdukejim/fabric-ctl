import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.directory.set_person_group import set_person_group
from fabriclib.domain.create_group import create_group
from fabriclib.domain.list_groups import list_groups
from fabriclib.domain.read_options import read_options
from fabriclib.domain.remove_group import remove_group
from fabriclib.domain.set_group_managers import set_group_managers
from fabriclib.domain.show_group import show_group

USAGE = """usage: fabricctl domain group list                       the domain's groups: kind, members
       fabricctl domain group create <name> [--description D]
       fabricctl domain group delete <name>              refused while it is in use, naming where
       fabricctl domain group scope <name>               its two levels: what it grants, its managers, its members
       fabricctl domain group managers <name> [--set a,b] [--add on|off] [--remove on|off] [--only-from G|none]
                                                         its managers (people or groups) and what they may do
       fabricctl domain group members <name> add|remove <person or group>
  Level 1 (scope, managers) is the tier above the group's; level 2 (members) that tier's or its managers' (manual
  1.6.12.5, 2.1.6.67). As root, acting for the Enterprise Admin."""


def _onoff(value, name):
    """Purpose: an on/off option's value.
    Inputs:  value — str; name — the option, for the message.
    Returns: bool.
    Fails:   ValidationError "<name> takes on or off".
    Feeds:   run_group_command (managers)."""
    if value not in ("on", "off"):
        raise ValidationError(f"{name} takes on or off")
    return value == "on"


def _scope(v, name):
    """Purpose: print a group's two levels.
    Inputs:  v — rendered vars; name — the group.
    Returns: None.
    Fails:   ValidationError from show_group.
    Feeds:   run_group_command (scope)."""
    g = show_group(v, name)
    s, m = g["scope"], g["managers"]
    print(f"{g['name']} ({g['kind']}){': ' + g['description'] if g['description'] else ''}")
    grants = ", ".join(f"{x['name']} ({x['as']})" for x in s["grants"]) or "none"
    print(f"  grants: {grants}; sudo rules: {', '.join(s['sudo']) or 'none'}; bundle: {s['bundle_name'] or 'none'}"
          + (f"; 802.1X VLAN {s['radius_vlan']}" if s["radius_vlan"] is not None else ""))
    print(f"  managers: {', '.join(m['managers']) or 'none'} (add: {'on' if m['add'] else 'off'}, remove: "
          f"{'on' if m['remove'] else 'off'}, only from: {m['only_from'] or 'any'})")
    for kind in ("people", "groups", "computers"):
        print(f"  {kind}: {', '.join(g['members'][kind]) or 'none'}")


def run_group_command(v, args):
    """Purpose: `fabricctl domain group …` (manual 4.6.11): only parses and routes to the group functions, as root
             (caller None).
    Inputs:  v — rendered vars; args — list of str after `group`.
    Returns: exit status: 0 done, 1 refused (with why), 2 usage.
    Fails:   OSError from the audit log; OpenBao sealed (load_secrets) propagate.
    Feeds:   samba/run_domain_command."""
    if not args or args[0] not in ("list", "create", "delete", "scope", "managers", "members") \
            or (args[0] != "list" and (len(args) < 2 or args[1].startswith("-"))):
        print(USAGE)
        return 2
    cmd, actor = args[0], getpass.getuser()
    try:
        if cmd == "list" and len(args) == 1:
            for g in list_groups(v)["groups"]:
                print(f"{g['name']:<32} {g['kind']:<10} {g['members']:>4} members  {g['description'][:60]}")
            return 0
        name, rest = (args[1], args[2:]) if len(args) > 1 else ("", [])
        if cmd == "create":
            done = create_group(v, actor, name, read_options(rest, ("--description",)).get("--description", ""),
                                source="cli")
            print(f"group {done['name']} created (gid {done['gid']})")
            return 0
        if cmd == "delete" and not rest:
            print(f"group {remove_group(v, actor, name, source='cli')['name']} deleted")
            return 0
        if cmd == "scope" and not rest:
            _scope(v, name)
            return 0
        if cmd == "managers":
            o = read_options(rest, ("--set", "--add", "--remove", "--only-from"))
            have = show_group(v, name)["managers"]
            managers = have["managers"] if "--set" not in o else [m for m in o["--set"].split(",") if m]
            only = have["only_from"] if "--only-from" not in o else ("" if o["--only-from"] == "none"
                                                                      else o["--only-from"])
            done = set_group_managers(v, actor, name, managers,
                                      _onoff(o["--add"], "--add") if "--add" in o else have["add"],
                                      _onoff(o["--remove"], "--remove") if "--remove" in o else have["remove"],
                                      only, source="cli")
            print(f"{done['name']}: managers {', '.join(done['managers']) or 'none'}"
                  + ("" if done["changed"] else " (unchanged)"))
            return 0
        if cmd == "members" and len(rest) == 2 and rest[0] in ("add", "remove"):
            done = set_person_group(v, actor, name, rest[1], rest[0] == "add", source="cli")
            print(f"{rest[1]}: {'in' if done['member'] else 'out of'} {name}"
                  + ("" if done["changed"] else " (already)"))
            return 0
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
