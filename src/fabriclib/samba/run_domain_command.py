import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.directory.add_machine import add_machine
from fabriclib.directory.sort_machines import sort_machines
from fabriclib.samba.domain_status import domain_status
from fabriclib.samba.set_domain_password_policy import set_domain_password_policy
from fabriclib.system.apply_changes import apply_changes

USAGE = """usage: fabricctl domain status                    the Windows domain: its DC, the roles it holds, the policy
       fabricctl domain password-policy [--minimum-length N] [--complexity on|off] [--history N]
           [--minimum-age-days N] [--maximum-age-days N] [--lockout-threshold N] [--lockout-minutes N]
           [--lockout-window-minutes N] [--no-apply]
       fabricctl domain add-machine <name> [--os linux|windows]   pre-create a machine (in its OS family's OU) with a
           one-time join password
       fabricctl domain sort-machines [--scheduled]   move Windows machines that joined themselves into OU=windows
  password-policy without options shows the policy in the settings; with options it changes those values (the whole
  policy is checked again) and applies them. add-machine prints the password once: give it to join-linux.sh
  --one-time on the machine (manual 4.6.6)."""

# option -> (policy key, type)
OPTIONS = {"--minimum-length": ("minimum_length", int), "--complexity": ("complexity", bool),
           "--history": ("history", int), "--minimum-age-days": ("minimum_age_days", int),
           "--maximum-age-days": ("maximum_age_days", int), "--lockout-threshold": ("lockout_threshold", int),
           "--lockout-minutes": ("lockout_minutes", int), "--lockout-window-minutes": ("lockout_window_minutes", int)}


def _changes(args):
    """Purpose: the policy values given as options.
    Inputs:  args — list of str after `password-policy`.
    Returns: dict {policy key: value}.
    Fails:   ValidationError for an unknown option, a missing value, a number that is not one, or a complexity other
             than on/off.
    Feeds:   run_domain_command."""
    out, rest = {}, [a for a in args if a != "--no-apply"]
    if len(rest) % 2:
        raise ValidationError("each option needs a value")
    for opt, value in zip(rest[::2], rest[1::2]):
        if opt not in OPTIONS:
            raise ValidationError(f"unknown option {opt}")
        key, kind = OPTIONS[opt]
        if kind is bool:
            if value not in ("on", "off"):
                raise ValidationError("--complexity takes on or off")
            out[key] = value == "on"
        elif not value.isdigit():
            raise ValidationError(f"{opt} takes a whole number")
        else:
            out[key] = int(value)
    return out


def run_domain_command(v, args):
    """Purpose: `fabricctl domain …` (manual 4.6.5): only routes to the domain functions.
    Inputs:  v — rendered vars; args — list of str after `domain`.
    Returns: exit status: 0 ok, 1 a refused change or a failed apply, 2 usage.
    Fails:   OSError from the vars file or the audit log (propagates).
    Feeds:   cli.main."""
    if not args or args[0] not in ("status", "password-policy", "add-machine", "sort-machines"):
        print(USAGE)
        return 2
    if args[0] == "sort-machines":
        if args[1:] not in ([], ["--scheduled"]):
            print(USAGE)
            return 2
        try:
            moved = sort_machines(v, getpass.getuser(), "timer" if args[1:] else "cli")
        except ValidationError as e:
            print(f"refused: {e}")
            return 1
        print(f"moved into OU=windows: {', '.join(moved)}" if moved else "no Windows machine to sort")
        return 0
    if args[0] == "add-machine":
        os_family = args[3] if len(args) == 4 and args[2] == "--os" else None
        if len(args) not in (2, 4) or (len(args) == 4 and os_family is None):
            print(USAGE)
            return 2
        try:
            password = add_machine(v, getpass.getuser(), args[1], os=os_family)
        except ValidationError as e:
            print(f"refused: {e}")
            return 1
        print(f"machine {args[1]} created in site {v['site_name']}; its one-time join password (shown once):")
        print(password)
        return 0
    if args[0] == "status":
        s = domain_status(v)
        print(f"domain {s['domain']} (realm {s['realm']}, NetBIOS {s['netbios']})")
        print(f"this DC {s['dc']}: {'running' if s['running'] else 'NOT running'}")
        for line in s["roles"]:
            print(f"  {line}")
        for line in s["policy"]:
            print(f"  {line}")
        return 0 if s["running"] else 1
    try:
        changes = _changes(args[1:])
        if not changes:
            for key, value in sorted((v.get("ad_password_policy") or {}).items()):
                print(f"{key}: {value}")
            return 0
        set_domain_password_policy(getpass.getuser(), changes)
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    if "--no-apply" in args:
        print("recorded; apply with: sudo fabricctl --apply")
        return 0
    ok, output = apply_changes("root", "cli")
    print("applied (the domain's policy is updated)" if ok else output[-2000:])
    return 0 if ok else 1
