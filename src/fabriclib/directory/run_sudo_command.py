import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.directory.add_sudo_rule import add_sudo_rule
from fabriclib.directory.list_sudo_rules import list_sudo_rules
from fabriclib.directory.remove_sudo_rule import remove_sudo_rule

USAGE = """usage: fabricctl sudo list                        the domain's sudo rules: fabric's, admins' own
       fabricctl sudo add <name> --who U,%G,... --commands C,... [--as U,...] [--hosts <host group>|ALL]
                                                  a rule: who (people, %groups) may run which commands (absolute
                                                  paths with their arguments, or ALL), as whom (default root), on
                                                  which host group (default ALL: every joined machine)
       fabricctl sudo remove <name>               remove one of fabric's rules (never an admin's own)
  Rules are stored in the domain's OU=sudoers and read by its joined Linux machines (never a fabric host). A rule
  granting ALL commands to everyone, or to a whole site, is refused (manual 4.6.6)."""

KINDS = {"fabric": "fabric", "grant": "a grant's: changed with fabricctl domain grant",
         "other": "not fabric's: read-only here"}


def _items(text):
    """Purpose: a comma-separated option value as a list.
    Inputs:  text — "a,b".
    Returns: list of str, stripped, empty items dropped.
    Fails:   never.
    Feeds:   run_sudo_command."""
    return [x.strip() for x in text.split(",") if x.strip()]


def _show(rules):
    """Purpose: print the sudo rules.
    Inputs:  rules — list_sudo_rules' list.
    Returns: None.
    Fails:   never.
    Feeds:   run_sudo_command."""
    if not rules:
        print("no sudo rules")
    for r in rules:
        where = r["host_group"] if r["host_group"] not in ("", "ALL") else ", ".join(r["hosts"]) or "(no hosts)"
        print(f"{r['name']} [{KINDS.get(r['kind'], r['kind'])}]: {', '.join(r['users'])} may run "
              f"{', '.join(r['commands'])} as {', '.join(r['run_as']) or 'root'} on {where}"
              + (f" ({', '.join(r['hosts']) or 'no machines'})" if r["host_group"] not in ("", "ALL") else ""))


def run_sudo_command(v, args):
    """Purpose: `fabricctl sudo …` (manual 4.6.6): only parses and routes to the sudo rule functions, as root (the
             audit names the CLI).
    Inputs:  v — rendered vars; args — list of str after `sudo`.
    Returns: exit status: 0 ok, 1 a refused change, 2 usage.
    Fails:   OSError from the audit log; OpenBao sealed (load_secrets) propagate.
    Feeds:   cli.main."""
    actor = getpass.getuser()
    cmd, rest = (args[0] if args else ""), args[1:]
    try:
        if cmd == "list" and not rest:
            _show(list_sudo_rules(v))
            return 0
        if cmd == "remove" and len(rest) == 1:
            print(f"sudo rule {remove_sudo_rule(v, actor, rest[0])['name']} removed")
            return 0
        opts = dict(zip(rest[1::2], rest[2::2]))
        if cmd == "add" and len(rest) % 2 == 1 and len(opts) * 2 == len(rest) - 1 \
                and set(opts) <= {"--who", "--commands", "--as", "--hosts"} and {"--who", "--commands"} <= set(opts):
            done = add_sudo_rule(v, actor, rest[0], _items(opts["--who"]), _items(opts["--commands"]),
                                 _items(opts.get("--as", "")), opts.get("--hosts"))
            hosts = ", ".join(done["hosts"]) or "(none: its host group has no machines yet)"
            print(f"sudo rule {done['name']} added; hosts: {hosts}")
            return 0
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
