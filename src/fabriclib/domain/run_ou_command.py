import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.domain.create_ou import create_ou
from fabriclib.domain.delete_ou import delete_ou
from fabriclib.domain.list_ous import list_ous
from fabriclib.domain.rename_ou import rename_ou

USAGE = """usage: fabricctl domain ou list                         the domain's folders, fabric's marked, their contents
       fabricctl domain ou create <parent> <name>        an admin's own OU, e.g. create people staff
       fabricctl domain ou rename <ou> <name>            e.g. rename people/staff office
       fabricctl domain ou delete <ou>                   refused while it holds anything, naming what
  An OU is named by its path below the domain (people/staff, machines/servers/web). An admin's own OUs go under
  people, service-accounts, groups and machines/servers|desktops|network; fabric's are never changed. OUs grant
  nothing (manual 1.6.12.7)."""


def run_ou_command(v, args):
    """Purpose: `fabricctl domain ou …` (manual 4.6.11): only parses and routes to the OU functions, as root.
    Inputs:  v — rendered vars; args — list of str after `ou`.
    Returns: exit status: 0 done, 1 refused (with why), 2 usage.
    Fails:   OSError from the audit log; OpenBao sealed (load_secrets) propagate.
    Feeds:   samba/run_domain_command."""
    actor = getpass.getuser()
    try:
        if args == ["list"]:
            for o in list_ous(v)["ous"]:
                h = o["holds"]
                mark = "fabric's" if o["fabric"] else "own" if o["own"] else "-"
                print(f"{o['path']:<40} {mark:<8} people {h['people']}, groups {h['groups']}, computers "
                      f"{h['computers']}, OUs {h['ous']}, other {h['other']}")
            return 0
        if len(args) == 3 and args[0] == "create":
            print(f"OU {create_ou(v, actor, args[1], args[2], source='cli')['path']} created")
            return 0
        if len(args) == 3 and args[0] == "rename":
            print(f"OU {args[1]} is now {rename_ou(v, actor, args[1], args[2], source='cli')['path']}")
            return 0
        if len(args) == 2 and args[0] == "delete":
            print(f"OU {delete_ou(v, actor, args[1], source='cli')['path']} deleted")
            return 0
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
