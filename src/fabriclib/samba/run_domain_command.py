import getpass
import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import INSTALL_DIR
from fabriclib.directory.add_machine import add_machine
from fabriclib.directory.set_machine_class import set_machine_class
from fabriclib.directory.sort_machines import sort_machines
from fabriclib.samba.clear_logon_policy import clear_logon_policy
from fabriclib.samba.domain_status import domain_status
from fabriclib.samba.host_logon_default import HOSTS_OU
from fabriclib.samba.logon_overview import logon_overview
from fabriclib.samba.set_domain_password_policy import set_domain_password_policy
from fabriclib.samba.set_logon_policy import set_logon_policy
from fabriclib.samba.sync_rodc_cache import sync_rodc_cache
from fabriclib.setup.common.sync_host_managed import sync_host_managed
from fabriclib.setup.errors import SetupError
from fabriclib.system.apply_changes import apply_changes
from fabriclib.vault.ssh.sign_ssh_hosts import sign_ssh_hosts

USAGE = """usage: fabricctl domain status                    the Windows domain: its DC, the roles it holds, the policy
       fabricctl domain password-policy [--minimum-length N] [--complexity on|off] [--history N]
           [--minimum-age-days N] [--maximum-age-days N] [--lockout-threshold N] [--lockout-minutes N]
           [--lockout-window-minutes N] [--no-apply]
       fabricctl domain add-machine <name> [--os linux|windows] [--class server|desktop] [--unmanaged]
           pre-create a machine (in its class's OS OU, the class by OS unless given: Linux a server, Windows a
           desktop; managed by fabric unless --unmanaged) with a one-time join password
       fabricctl domain machine class <name> server|desktop   move a machine to that class: who may sign in to it
           remotely (SSH, RDP) is that class's <site>-<class>-remote-users
       fabricctl domain sort-machines [--scheduled]   Windows machines that joined themselves into their class's
           OU=windows (Windows Server a server, else a desktop); Linux
           machines joined with an admin's password into <site>-fabric-machines (each once)
       fabricctl domain host-managed [--scheduled]   this fabric host's management (Kerberos for SSH, the
           domain's names from fabric's DNS) applied or removed as its account's <site>-fabric-machines membership says
       fabricctl domain rodc-cache [--scheduled]   at a site whose DC is read-only: the site's people and machines
           kept in <site>-rodc-cache and cached at the read-only DC now (2.1.6.55)
       fabricctl domain ssh-hosts [--scheduled]   SSH host certificates: the managed machines' published host keys
           signed by fabric's host CA and written back, this host's own applied (while SSH certificates are on)
       fabricctl domain logon show [<ou>]          who may sign in to the site's machines, per OU
       fabricctl domain logon set <ou> [--console G,...] [--remote G,...] [--no-apply]
       fabricctl domain logon clear <ou> [--no-apply]
  password-policy without options shows the policy in the settings; with options it changes those values (the whole
  policy is checked again) and applies them. add-machine prints the password once: give it to join-linux.sh
  --one-time on the machine (manual 4.6.6). logon: <ou> is a path below the site's OU (machines, machines/servers,
  machines/desktops/windows, …;
  site for the site's OU itself); set names the groups allowed at the keyboard (--console) and remotely (--remote:
  RDP, SSH), a right left out kept as it is; clear lets the OU take its parent's policy again. fabric-break-glass and
  each machine's local Administrators are always allowed (manual 4.6.8)."""

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


def _groups(text):
    """Purpose: a --console or --remote value as a list of group names.
    Inputs:  text — "G1,G2" ("" for none).
    Returns: list of str, stripped, empty items dropped.
    Fails:   never.
    Feeds:   _logon."""
    return [g.strip() for g in text.split(",") if g.strip()]


def _show(o):
    """Purpose: print who may sign in, per OU.
    Inputs:  o — logon_overview's dict.
    Returns: None.
    Fails:   never.
    Feeds:   run_domain_command (status), _logon (show)."""
    print(f"who may sign in to the machines of {o['site']}" + (
        " (the log-on rights of before 0.9, on the site's OU: the first change makes them its policy)"
        if o["legacy"] else "") + ":")
    if o.get("unapplied"):
        print("  warning: these per-OU policies are in this site's settings, but its domain controller is read-only "
              "and never applies them (saved before such changes were refused): they have no effect. Make them at "
              "the site above, and remove logon_policies from this site's settings (2.1.6.52)")
    elif o.get("read_only"):
        print("  this site's domain controller is read-only: who may sign in is changed at the site above")
    if o["error"]:
        print(f"  could not be read: {o['error']}")
    for p in o["policies"]:
        console = "(as above)" if p["console"] is None else ", ".join(p["console"]) or "(nobody)"
        print(f"  {p['ou'] or 'site'}: console {console}; "
              f"remote {', '.join(p['remote']) or '(nobody)'}")
    if not o["policies"]:
        print("  that OU has no policy of its own: it takes its parent's")
    print(f"  always, everywhere: {', '.join(o['always'])}")


def _logon(v, args):
    """Purpose: `fabricctl domain logon show|set|clear` (manual 4.6.8): only parses and routes.
    Inputs:  v — rendered vars; args — list of str after `logon`.
    Returns: exit status: 0 ok, 1 refused or a failed apply, 2 usage.
    Fails:   OSError from the settings or the audit log (propagates).
    Feeds:   run_domain_command."""
    op, rest = (args[0] if args else ""), args[1:]
    no_apply = "--no-apply" in rest
    rest = [a for a in rest if a != "--no-apply"]
    opts = dict(zip(rest[1::2], rest[2::2]))
    try:
        if op == "show" and len(rest) <= 1:
            _show(logon_overview(v, rest[0] if rest else None))
            return 0
        if op == "clear" and len(rest) == 1:
            clear_logon_policy(getpass.getuser(), rest[0], v=v)
            print(f"{rest[0]}: its own log-on policy cleared ("
                  + ("back to the default: the fabric admins, 2.1.6.53)" if rest[0].strip("/").lower() == HOSTS_OU
                     else "it takes its parent's)"))
        elif op == "set" and len(rest) in (3, 5) and set(opts) <= {"--console", "--remote"} \
                and len(opts) * 2 == len(rest) - 1:
            done = set_logon_policy(v, getpass.getuser(), rest[0],
                                    _groups(opts["--console"]) if "--console" in opts else None,
                                    _groups(opts["--remote"]) if "--remote" in opts else None)
            print(f"{done['ou'] or 'site'}: console {', '.join(done['console']) or '(nobody)'}; "
                  f"remote {', '.join(done['remote']) or '(nobody)'}")
        else:
            print(USAGE)
            return 2
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    if no_apply:
        print("recorded; apply with: sudo fabricctl --apply")
        return 0
    ok, output = apply_changes("root", "cli")
    print("applied (the site's log-on GPOs are updated)" if ok else output[-2000:])
    return 0 if ok else 1


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
    print(f"{done['account']}$ is {'in' if done['managed'] else 'not in'} {v.get('site_name')}-fabric-machines: "
          f"fabric's management {'applied' if done['managed'] else 'removed'}")
    for line in done["changes"] or ["nothing to change"]:
        print(f"  {line}")
    return 0


def _rodc_cache(v, args):
    """Purpose: `fabricctl domain rodc-cache [--scheduled]` (manual 4.6.5.6): only parses and routes to sync_rodc_cache,
             and says what it did.
    Inputs:  v — rendered vars; args — list of str after `rodc-cache`.
    Returns: exit status: 0 done, 1 refused (not a read-only DC's site by hand; the lists, the writable DC or the
             preload refusing; accounts of another site reached), 2 usage. With --scheduled (the fabric-rodc-cache
             timer) a site whose DC is not read-only is 0: nothing to keep.
    Fails:   OSError from the secrets (propagates).
    Feeds:   run_domain_command."""
    if args not in ([], ["--scheduled"]):
        print(USAGE)
        return 2
    if v.get("ad_dc_type") != "rodc":
        print(("nothing to do: " if args else "refused: ") + "this site's domain controller is not read-only: every "
              "account signs in at it already")
        return 0 if args else 1
    try:
        lines = sync_rodc_cache(v)
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    for line in lines:
        print(line)
    return 0


def _ssh_hosts(v, args):
    """Purpose: `fabricctl domain ssh-hosts [--scheduled]` (manual 1.6.11.9.8): only parses and routes to
             sign_ssh_hosts, and says what it signed, withdrew and changed.
    Inputs:  v — rendered vars; args — list of str after `ssh-hosts`.
    Returns: exit status: 0 done (off: this host's part removed), 1 refused (OpenBao locked, the directory or sshd
             refusing), 2 usage.
    Fails:   OSError from the files or the audit log (propagates).
    Feeds:   run_domain_command."""
    if args not in ([], ["--scheduled"]):
        print(USAGE)
        return 2
    try:
        done = sign_ssh_hosts(v, os.path.join(INSTALL_DIR, "config"), getpass.getuser(),
                              "timer" if args else "cli")
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    if not done["on"]:
        print("SSH certificates are off: no host certificates signed; this host's own removed")
    else:
        print(f"host CA {done['ca_fingerprint']}")
        for name in done["prepared"]:
            print(f"  {name}: may publish its host keys now")
        for m in done["machines"]:
            what = ("certificates withdrawn (not managed, or disabled)" if m["withdrawn"] else m["error"]
                    or f"{m['signed']} signed, {m['kept']} kept")
            print(f"  {m['name']}: {what}" + "".join(f"; refused: {r}" for r in m["refused"]))
    for key in done.get("revoked") or []:
        print(f"  revoked until its certificate's end: {key[:60]}…")
    for line in done["host"] or ["this host: nothing to change"]:
        print(f"  {line}")
    return 1 if any(m["error"] for m in done["machines"]) else 0


def _machine(v, args):
    """Purpose: `fabricctl domain machine class <name> server|desktop` (manual 4.6.6): only routes to
             set_machine_class (2.1.6.36 as revised 2026-10-13).
    Inputs:  v — rendered vars; args — list of str after `machine`.
    Returns: exit status: 0 done (or already so), 1 refused, 2 usage.
    Fails:   OSError from the audit log (propagates).
    Feeds:   run_domain_command."""
    if len(args) != 3 or args[0] != "class" or args[1].startswith("-"):
        print(USAGE)
        return 2
    try:
        done = set_machine_class(v, getpass.getuser(), args[1], args[2])
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(f"{done['name']} is a {done['class']} {'now' if done['changed'] else 'already'} ({done['dn']}); who may "
          f"sign in to it remotely: {v['site_name']}-{done['class']}-remote-users and the groups nested in it")
    return 0


def run_domain_command(v, args):
    """Purpose: `fabricctl domain …` (manual 4.6.5): only routes to the domain functions.
    Inputs:  v — rendered vars; args — list of str after `domain`.
    Returns: exit status: 0 ok, 1 a refused change or a failed apply, 2 usage.
    Fails:   OSError from the vars file or the audit log (propagates).
    Feeds:   cli.main."""
    if not args or args[0] not in ("status", "password-policy", "add-machine", "machine", "sort-machines", "logon",
                                   "host-managed", "rodc-cache", "ssh-hosts"):
        print(USAGE)
        return 2
    if args[0] == "rodc-cache":
        return _rodc_cache(v, args[1:])
    if args[0] == "ssh-hosts":
        return _ssh_hosts(v, args[1:])
    if args[0] == "host-managed":
        return _host_managed(v, args[1:])
    if args[0] == "logon":
        return _logon(v, args[1:])
    if args[0] == "machine":
        return _machine(v, args[1:])
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
            print(f"moved into their class's OU=windows: {', '.join(moved['sorted'])}")
        if moved["adopted"]:
            print(f"managed by fabric now (in {v['site_name']}-fabric-machines): {', '.join(moved['adopted'])}")
        if not moved["sorted"] and not moved["adopted"]:
            print("nothing to sort")
        return 0
    if args[0] == "add-machine":
        rest = args[2:]
        managed = "--unmanaged" not in rest
        rest = [a for a in rest if a != "--unmanaged"]
        given = dict(zip(rest[::2], rest[1::2]))
        if len(args) < 2 or args[1].startswith("-") or len(rest) % 2 or set(given) - {"--os", "--class"} \
                or len(given) * 2 != len(rest):
            print(USAGE)
            return 2
        try:
            password = add_machine(v, getpass.getuser(), args[1], os=given.get("--os"), managed=managed,
                                   machine_class=given.get("--class"))
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
        try:
            _show(logon_overview(v))
        except ValidationError as e:
            print(f"who may sign in: the setting is refused: {e}")
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
