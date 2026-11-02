import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.grants.add_grant import add_grant
from fabriclib.grants.explain_grant import explain_grant
from fabriclib.grants.list_grants import list_grants
from fabriclib.grants.remove_grant import remove_grant
from fabriclib.grants.set_grant import set_grant
from fabriclib.grants.show_grant import show_grant
from fabriclib.grants.read_grant_fields import refuse_run_as
from fabriclib.grants.sync_grants import sync_grants

USAGE = """usage: fabricctl domain grant list               the grants: who, rights, where, whom; templates
       fabricctl domain grant show <name>          one grant: the people and machines it reaches, its groups and sets
       fabricctl domain grant add <name> --who G,... --where G,... [--template T] [--restrict] [rights]
       fabricctl domain grant add <name> --who G,... --networks plan,options,scan --sites S,...|all
       fabricctl domain grant set <name> [--who G,...] [--where G,...] [rights]
       fabricctl domain grant remove <name>
       fabricctl domain grant explain <person> [<machine>]   which grants reach them, and why
       fabricctl domain grant sync [--scheduled]   compile the grants again (the fabric-grants timer, every 5 minutes)
  rights: --signin keyboard,remote  --sudo ALL|/path/cmd,...  --local-admin yes|no  --people edit,reset,unlock,
  disable,add  --machines add,move,disable,remove,groups  --networks plan,options,scan (with --sites S,...|all)
  --description TEXT  (a list's value `none` clears it)
  sudo always runs as root (a --run-as other than root is refused, 2.1.6.90).
  who and where: groups, a person or machine must be in all of them. A restricting grant (--restrict) names where,
  the right it narrows (--signin, --local-admin) and who alone keeps it there. Refused: the tiers' groups, the hosts
  that run a DC, sudo of every command for everyone, an empty who or where. Networks rights hold at their sites, so
  a grant of them alone needs no --where (manual 1.6.13.12). Changes are made at the root's writable DC and compiled
  at once (manual 4.6.10)."""

LIST_OPTIONS = {"--who": "who", "--where": "where", "--signin": "signin", "--sudo": "sudo", "--people": "people",
                "--machines": "machines", "--networks": "networks", "--sites": "sites"}


def _fields(rest):
    """Purpose: a grant's fields from the command's options.
    Inputs:  rest — list of str after the grant's name.
    Returns: (fields dict, template name or None).
    Fails:   ValidationError for an unknown option, an option without its value, --local-admin other than yes/no,
             --run-as other than root.
    Feeds:   run_grant_command."""
    fields, template, args = {}, None, list(rest)
    if "--restrict" in args:
        args.remove("--restrict")
        fields["kind"] = "restrict"
    if len(args) % 2:
        raise ValidationError("each option needs a value")
    for opt, value in zip(args[::2], args[1::2]):
        if opt in LIST_OPTIONS:
            fields[LIST_OPTIONS[opt]] = [] if value == "none" else [x.strip() for x in value.split(",") if x.strip()]
        elif opt == "--local-admin":
            if value not in ("yes", "no"):
                raise ValidationError("--local-admin takes yes or no")
            fields["local_admin"] = value == "yes"
        elif opt == "--description":
            fields["description"] = value
        elif opt == "--template":
            template = value
        elif opt == "--run-as":                   # root alone, what a grant's sudo always is (2.1.6.90)
            refuse_run_as([x.strip() for x in value.split(",")])
        else:
            raise ValidationError(f"unknown option {opt}")
    return fields, template


def _rights(g):
    """Purpose: a grant's rights in one line.
    Inputs:  g — a stored grant.
    Returns: str.
    Fails:   never.
    Feeds:   _print_grant."""
    parts = []
    if g["signin"]:
        parts.append("sign-in " + "+".join(g["signin"]))
    if g["sudo"]:
        parts.append("sudo " + ("every command" if g["sudo"] == ["ALL"] else ",".join(g["sudo"])))
    if g["local_admin"]:
        parts.append("local administrator")
    if g["people"]:
        parts.append("people: " + ",".join(g["people"]))
    if g["machines"]:
        parts.append("machines: " + ",".join(g["machines"]))
    if g.get("networks"):
        parts.append("networks: " + ",".join(g["networks"]) + " at " + ",".join(g.get("sites") or []))
    return "; ".join(parts) or "nothing"


def _print_grant(g):
    """Purpose: print one grant's summary line.
    Inputs:  g — a grant summary (grants_tool's list or show).
    Returns: None.
    Fails:   never.
    Feeds:   run_grant_command."""
    c = g["counts"]
    kind = "restricts" if g["kind"] == "restrict" else "gives"
    on = f" on {' & '.join(g['where'])}" if g["where"] else ""
    print(f"{g['name']}: {' & '.join(g['who'])} {kind} {_rights(g)}{on} "
          f"({c['people']} people, {c['machines']} machines" + (f", {c['where_people']} people managed"
                                                                 if c["where_people"] else "") + ")"
          + (" — reaches nobody" if g["reaches_nobody"] else ""))


def _explain(out):
    """Purpose: print grant explain's answer.
    Inputs:  out — explain_grant's result.
    Returns: None.
    Fails:   never.
    Feeds:   run_grant_command."""
    where = f" on {out['machine']}" if out["machine"] else ""
    if out["never"]:
        print(f"{out['person']}: {out['never']}")
    for g in out["grants"]:
        missing = g["who_missing"] + g.get("where_missing", [])
        why = "reaches them" + where if g["reaches"] else "not: missing " + ", ".join(missing) if missing \
            else "not (left out: see above)"
        print(f"  {g['name']} ({g['kind']}): {why}")
    on = out["on_machine"]
    if on is not None:
        print(f"{out['person']}{where}: keyboard {'yes' if on['keyboard'] else 'no'}, remote "
              f"{'yes' if on['remote'] else 'no'}, local administrator {'yes' if on['local-admin'] else 'no'}, sudo "
              f"{', '.join(on['sudo']) or 'none'} (BUILTIN\\Administrators and local-admin always sign in)")


def run_grant_command(v, args, container="samba"):
    """Purpose: `fabricctl domain grant …` (manual 4.6.10): only parses and routes to the grants functions, as root (the
             audit names the CLI).
    Inputs:  v — rendered vars; args — list of str after `grant`; container — the DC's container.
    Returns: exit status: 0 ok, 1 refused, 2 usage. `sync --scheduled` (the timer) is 0 at a DC that does not compile.
    Fails:   OSError from the audit log (propagates).
    Feeds:   samba/run_domain_command."""
    actor = getpass.getuser()
    cmd, rest = (args[0] if args else ""), args[1:]
    try:
        if cmd == "list" and not rest:
            out = list_grants(v, container)
            for g in out["grants"]:
                _print_grant(g)
            if not out["grants"]:
                print("no grants")
            print("templates: " + ", ".join(sorted(out["templates"])))
            return 0
        if cmd == "show" and len(rest) == 1:
            g = show_grant(v, rest[0], container)
            _print_grant(g)
            print(f"  people: {', '.join(g['who_people']) or '(none)'}")
            print(f"  machines: {', '.join(g['where_machines']) or '(none)'}")
            if g["where_people_names"]:
                print(f"  people managed: {', '.join(g['where_people_names'])}")
            print(f"  groups: {', '.join(g['groups'])}; sets: {', '.join(map(str, g['sets'])) or '(none)'}"
                  + (f"; sudo rule {g['sudo_rule']}" if g["sudo_rule"] else ""))
            if g["people"] or g["machines"]:
                print("  its people and machines rights are checked by fabric-agent on every call (D4, 1.6.12.15)")
            if g.get("networks"):
                print("  its networks rights are checked by fabric-agent on every call, at its sites (1.6.13.12)")
            return 0
        if cmd == "remove" and len(rest) == 1:
            done = remove_grant(v, actor, rest[0], container=container)
            print(f"grant {rest[0]} removed; compiled: {len(done['changed'])} change(s)")
            return 0
        if cmd == "explain" and len(rest) in (1, 2):
            _explain(explain_grant(v, rest[0], rest[1] if len(rest) == 2 else None, container))
            return 0
        if cmd == "sync" and rest in ([], ["--scheduled"]):
            done = sync_grants(v, actor, "timer" if rest else "cli", container)
            if "skipped" in done:
                print(f"nothing to do: {done['skipped']}")
                return 0 if rest else 1
            for line in done["changed"] or ["nothing to change"]:
                print(f"  {line}")
            return 0
        if cmd in ("add", "set") and rest and not rest[0].startswith("-"):
            fields, template = _fields(rest[1:])
            if cmd == "add":
                done = add_grant(v, actor, rest[0], fields, template, container=container)
            elif template or not fields:
                raise ValidationError("set takes the fields to change (no --template)")
            else:
                done = set_grant(v, actor, rest[0], fields, container=container)
            print(f"grant {rest[0]} {'added' if cmd == 'add' else 'changed'}; compiled: {len(done['changed'])} "
                  "change(s)")
            for line in done["changed"]:
                print(f"  {line}")
            return 0
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
