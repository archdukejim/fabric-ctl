import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.directory.set_person_enabled import set_person_enabled
from fabriclib.domain.edit_person import edit_person
from fabriclib.domain.person_fields import FIELDS
from fabriclib.domain.read_options import read_options
from fabriclib.domain.unlock_person import unlock_person

OPTIONS = {"--" + f.replace("_", "-"): f for f in FIELDS}
USAGE = """usage: fabricctl domain person edit <uid> [--first F] [--last L] [--name N] [--email E] [--phone P]
         [--mobile M] [--title T] [--department D] [--company C] [--office O] [--city C] [--state S]
         [--country CC] [--manager UID] [--employee-id ID]   a person's details (an empty value clears one;
         the names are never cleared)
       fabricctl domain person unlock <uid>          their lockout cleared (the password kept)
       fabricctl domain person disable|enable <uid>  block every sign-in at once (sessions end), or allow it again
  As root, acting for the Enterprise Admin: fabric-agent's check still refuses AD's top tier and fabric's own
  accounts (manual 1.6.12.2). Reset, add and remove are `fabricctl people`'s."""


def run_person_command(v, args):
    """Purpose: `fabricctl domain person …` (manual 4.6.11): only parses and routes to the person functions, as root
             (caller None), the audit naming the CLI.
    Inputs:  v — rendered vars; args — list of str after `person`.
    Returns: exit status: 0 done, 1 refused (with why), 2 usage.
    Fails:   OSError from the audit log; OpenBao sealed (load_secrets) propagate.
    Feeds:   samba/run_domain_command."""
    if len(args) < 2 or args[0] not in ("edit", "unlock", "disable", "enable") or args[1].startswith("-"):
        print(USAGE)
        return 2
    cmd, uid, rest, actor = args[0], args[1], args[2:], getpass.getuser()
    try:
        if cmd == "edit":
            o = read_options(rest, tuple(OPTIONS))
            done = edit_person(v, actor, uid, {OPTIONS[k]: value for k, value in o.items()}, source="cli")
            print(f"{uid}: {', '.join(done['changed']) + ' changed' if done['changed'] else 'nothing to change'} "
                  f"(name: {done['name']}, e-mail: {done['email']})")
            return 0
        if rest:
            print(USAGE)
            return 2
        if cmd == "unlock":
            done = unlock_person(v, actor, uid, source="cli")
            print(f"{uid}: unlocked" if done["changed"] else f"{uid}: not locked out")
            return 0
        done = set_person_enabled(v, actor, uid, cmd == "enable", source="cli")
        print(f"{uid}: {cmd}d" if done["changed"] else f"{uid}: already {cmd}d")
        return 0
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
