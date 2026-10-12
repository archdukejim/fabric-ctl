import getpass

from fabriclib.common.ask import ask
from fabriclib.common.errors import ValidationError
from fabriclib.directory.create_person import create_person
from fabriclib.directory.list_people import list_people
from fabriclib.directory.remove_person import remove_person
from fabriclib.directory.reset_sign_in import reset_sign_in
from fabriclib.directory.set_person_enabled import set_person_enabled
from fabriclib.directory.set_person_group import set_person_group

USAGE = """usage: fabricctl people list                      every person: user name, name, site, state, groups
       fabricctl people show <uid>                one person
       fabricctl people add <uid> --first F --last L --email E
                                                  a new person of this site; prints their one-time password once
       fabricctl people reset <uid>               a new one-time password, TOTP removed, sessions ended
       fabricctl people disable|enable <uid>      block every sign-in at once (sessions end), or allow it again
       fabricctl people remove <uid> [--confirm <uid>]
                                                  remove them and revoke their certificates (asks for the user name
                                                  typed back; --confirm gives it unattended)
       fabricctl people groups <uid>              the groups they are in
       fabricctl people group add|remove <group> <uid>
  Only this site's people can be changed. A one-time password is shown on this terminal only, never logged."""


def _options(args, names):
    """Purpose: `--name value` options from the words after a command.
    Inputs:  args — list of str; names — the options allowed (e.g. ("--first", "--last")).
    Returns: dict {name: value}.
    Fails:   ValidationError for an unknown option, a missing value or a stray word.
    Feeds:   run_people_command."""
    out = {}
    if len(args) % 2:
        raise ValidationError("each option needs a value")
    for opt, value in zip(args[::2], args[1::2]):
        if opt not in names:
            raise ValidationError(f"unknown option {opt}")
        out[opt] = value
    return out


def _person(v, uid):
    """Purpose: one person from the directory's list.
    Inputs:  v — fabric vars; uid — the user name.
    Returns: the list's entry {uid, name, mail, locked, groups, site, uidNumber}.
    Fails:   ValidationError "no such person: <uid>"; list_people's.
    Feeds:   run_people_command (show, groups)."""
    found = [u for u in list_people(v)["users"] if u["uid"] == uid]
    if not found:
        raise ValidationError(f"no such person: {uid}")
    return found[0]


def _run(v, args, actor):
    """Purpose: one people command, after the usage check.
    Inputs:  v — fabric vars; args — list of str after `people`; actor — the audit's name.
    Returns: exit status 0, or 2 for a usage error.
    Fails:   ValidationError from the directory functions.
    Feeds:   run_people_command."""
    cmd, rest = args[0], args[1:]
    if cmd == "list" and not rest:
        for u in list_people(v)["users"]:
            state = "locked" if u["locked"] else "active"
            print(f"{u['uid']:<20} {u['name'][:28]:<28} {u['site']:<12} {state:<7} {', '.join(u['groups'])}")
        return 0
    if cmd in ("show", "groups") and len(rest) == 1:
        u = _person(v, rest[0])
        if cmd == "groups":
            print("\n".join(u["groups"]))
            return 0
        for label, key in (("user name", "uid"), ("name", "name"), ("e-mail", "mail"), ("site", "site"),
                           ("uid number", "uidNumber")):
            print(f"{label + ':':<12} {u[key]}")
        print(f"{'state:':<12} {'locked or disabled' if u['locked'] else 'active'}")
        print(f"{'groups:':<12} {', '.join(u['groups'])}")
        return 0
    if cmd == "add" and rest:
        o = _options(rest[1:], ("--first", "--last", "--email"))
        password = create_person(v, actor, rest[0], o.get("--first"), o.get("--last"), o.get("--email"),
                                 source="cli")
        print(f"{rest[0]} created in site {v['site_name']}; their one-time password (shown once):\n{password}")
        return 0
    if cmd == "reset" and len(rest) == 1:
        password = reset_sign_in(v, actor, rest[0], privileged=True, source="cli")
        print(f"{rest[0]}: new one-time password (shown once), TOTP removed, sessions ended:\n{password}")
        return 0
    if cmd in ("disable", "enable") and len(rest) == 1:
        done = set_person_enabled(v, actor, rest[0], cmd == "enable", privileged=True, source="cli")
        print(f"{rest[0]}: {cmd}d" if done["changed"] else f"{rest[0]}: already {cmd}d")
        return 0
    if cmd == "remove" and rest:
        confirm = _options(rest[1:], ("--confirm",)).get("--confirm")
        if confirm is None:
            try:
                confirm = ask("people.remove.confirm",
                              f"Remove {rest[0]} and revoke their certificates? Type the user name to confirm: ")
            except EOFError:
                confirm = ""
        done = remove_person(v, actor, rest[0], confirm, privileged=True, source="cli")
        print(f"{rest[0]} removed; certificates revoked: {', '.join(done['revoked']) or 'none'}")
        return 0
    if cmd == "group" and len(rest) == 3 and rest[0] in ("add", "remove"):
        done = set_person_group(v, actor, rest[1], rest[2], rest[0] == "add", privileged=True, source="cli")
        state = "in" if done["member"] else "out of"
        print(f"{rest[2]}: {state} {rest[1]}" + ("" if done["changed"] else " (already)"))
        return 0
    print(USAGE)
    return 2


def run_people_command(v, args):
    """Purpose: `fabricctl people …` (manual 4.6.3): only routes to the people functions, as root (the audit names the
             CLI), with an admin's rights.
    Inputs:  v — rendered vars; args — list of str after `people`.
    Returns: exit status: 0 ok, 1 a refused change, 2 usage.
    Fails:   OSError from the audit log; OpenBao sealed (load_secrets) propagate.
    Feeds:   cli.main."""
    if not args or args[0] not in ("list", "show", "add", "reset", "disable", "enable", "remove", "groups", "group"):
        print(USAGE)
        return 2
    try:
        return _run(v, args, getpass.getuser())
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
