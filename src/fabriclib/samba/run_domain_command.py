import getpass
import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import INSTALL_DIR
from fabriclib.directory.add_machine import add_machine
from fabriclib.directory.sort_machines import sort_machines
from fabriclib.grants.run_grant_command import run_grant_command
from fabriclib.samba.domain_status import domain_status
from fabriclib.samba.set_domain_password_policy import set_domain_password_policy
from fabriclib.samba.set_tier_password_policy import set_tier_password_policy
from fabriclib.setup.common.sync_host_managed import sync_host_managed
from fabriclib.setup.errors import SetupError
from fabriclib.system.apply_changes import apply_changes

USAGE = """usage: fabricctl domain status                    the Windows domain: its DC, the roles it holds, the policy
       fabricctl domain password-policy [--tier enterprise-admin|directory-admins] [--minimum-length N]
           [--complexity on|off] [--history N] [--minimum-age-days N] [--maximum-age-days N] [--lockout-threshold N]
           [--lockout-minutes N] [--lockout-window-minutes N] [--no-apply]
       fabricctl domain add-machine <name> [--type server|desktop|network] [--unmanaged]   pre-create a machine
           (in its type's OU and group, and this site's group; managed by fabric unless --unmanaged) with a one-time
           join password
       fabricctl domain sort-machines [--scheduled]   Windows machines that joined themselves filed by type (a Server
           edition a server, else a desktop); Linux machines joined with an admin's password into fabric-managed
           (each once)
       fabricctl domain grant list|show|add|set|remove|explain|sync ...   who may do what, where (grants)
       fabricctl domain host-managed [--scheduled]   this fabric host's management (Kerberos for SSH, the
           domain's names from fabric's DNS) applied or removed as its account's fabric-managed membership says
  password-policy without options shows the policy in the settings; with options it changes those values (the whole
  policy is checked again) and applies them. Without --tier it is the domain's default policy (everyone's but the
  tiers'); --tier enterprise-admin is fabric-admin's own (its lockout never 0: break glass unlocks by itself),
  --tier directory-admins the Directory Administrators' (2.1.6.71): set only here, as root.
  add-machine prints the password once: give it to join-linux.sh
  --one-time on the machine (manual 4.6.6)."""

# --tier's names -> the tiers' policies' keys (2.1.6.71)
TIER_NAMES = {"enterprise-admin": "enterprise_admin", "directory-admins": "directory_admins"}
# option -> (policy key, type)
OPTIONS = {"--minimum-length": ("minimum_length", int), "--complexity": ("complexity", bool),
           "--history": ("history", int), "--minimum-age-days": ("minimum_age_days", int),
           "--maximum-age-days": ("maximum_age_days", int), "--lockout-threshold": ("lockout_threshold", int),
           "--lockout-minutes": ("lockout_minutes", int), "--lockout-window-minutes": ("lockout_window_minutes", int)}


def _changes(args):
    """Purpose: the policy values given as options.
    Inputs:  args — list of str after `password-policy`, without --tier and --no-apply.
    Returns: dict {policy key: value}.
    Fails:   ValidationError for an unknown option, a missing value, a number that is not one, or a complexity other
             than on/off.
    Feeds:   run_domain_command."""
    out, rest = {}, list(args)
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


def _host_managed(v, args):
    """Purpose: `fabricctl domain host-managed [--scheduled]` (manual 1.6.11.11): only parses and routes to
             sync_host_managed, and says what it found and changed.
    Inputs:  v — rendered vars; args — list of str after `host-managed`.
    Returns: exit status: 0 done, 1 refused (not a member; the DC not answering; sshd refusing), 2 usage. With
             --scheduled (the fabric-host-managed timer) a host that is not a member is 0: nothing to keep in step.
    Fails:   OSError from the record (propagates).
    Feeds:   run_domain_command."""
    if args not in ([], ["--scheduled"]):
        print(USAGE)
        return 2
    try:
        done = sync_host_managed(v, os.path.join(INSTALL_DIR, "config"))
    except ValidationError as e:
        print(f"{'nothing to do' if args else 'refused'}: {e}")
        return 0 if args else 1
    except SetupError as e:
        print(f"refused: {e}")
        return 1
    print(f"{done['account']}$ is {'in' if done['managed'] else 'not in'} fabric-managed: "
          f"fabric's management {'applied' if done['managed'] else 'removed'}")
    for line in done["changes"] or ["nothing to change"]:
        print(f"  {line}")
    return 0


def run_domain_command(v, args):
    """Purpose: `fabricctl domain …` (manual 4.6.5): only routes to the domain functions.
    Inputs:  v — rendered vars; args — list of str after `domain`.
    Returns: exit status: 0 ok, 1 a refused change or a failed apply, 2 usage.
    Fails:   OSError from the vars file or the audit log (propagates). password-policy --tier is refused with why
             (exit 1) for an unknown tier or a policy the checks refuse (check_tier_policies).
    Feeds:   cli.main."""
    if not args or args[0] not in ("status", "password-policy", "add-machine", "sort-machines", "grant",
                                   "host-managed"):
        print(USAGE)
        return 2
    if args[0] == "grant":
        return run_grant_command(v, args[1:])
    if args[0] == "host-managed":
        return _host_managed(v, args[1:])
    if args[0] == "sort-machines":
        if args[1:] not in ([], ["--scheduled"]):
            print(USAGE)
            return 2
        try:
            moved = sort_machines(v, getpass.getuser(), "timer" if args[1:] else "cli")
        except ValidationError as e:
            print(f"refused: {e}")
            return 1
        if moved["sorted"]:
            print(f"filed by type (OU=servers or OU=desktops): {', '.join(moved['sorted'])}")
        if moved["adopted"]:
            print(f"managed by fabric now (in fabric-managed): {', '.join(moved['adopted'])}")
        if not moved["sorted"] and not moved["adopted"]:
            print("nothing to sort")
        return 0
    if args[0] == "add-machine":
        rest = args[2:]
        managed = "--unmanaged" not in rest
        rest = [a for a in rest if a != "--unmanaged"]
        kind = rest[1] if len(rest) == 2 and rest[0] == "--type" else None
        if len(args) < 2 or args[1].startswith("-") or (rest and kind is None):
            print(USAGE)
            return 2
        try:
            password = add_machine(v, getpass.getuser(), args[1], type=kind, managed=managed)
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
    rest, tier = [a for a in args[1:] if a != "--no-apply"], None
    if "--tier" in rest:
        at = rest.index("--tier")
        tier = rest[at + 1] if at + 1 < len(rest) else ""
        rest = rest[:at] + rest[at + 2:]
    try:
        if tier is not None and tier not in TIER_NAMES:
            raise ValidationError(f"--tier takes enterprise-admin or directory-admins, not {tier!r}")
        changes = _changes(rest)
        if not changes:
            shown = ((v.get("ad_tier_password_policies") or {}).get(TIER_NAMES[tier]) if tier
                     else v.get("ad_password_policy")) or {}
            for key, value in sorted(shown.items()):
                print(f"{key}: {value}")
            return 0
        if tier:
            set_tier_password_policy(getpass.getuser(), TIER_NAMES[tier], changes)
        else:
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
