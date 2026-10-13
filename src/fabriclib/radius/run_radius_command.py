import sys

from fabriclib.common.ask import ask_secret
from fabriclib.common.errors import ValidationError
from fabriclib.radius.add_radius_client import add_radius_client
from fabriclib.radius.coa.coa_session import coa_session
from fabriclib.radius.list_auth_log import list_auth_log
from fabriclib.radius.map_radius_group import map_radius_group
from fabriclib.radius.radius_overview import radius_overview
from fabriclib.radius.radius_sessions import radius_sessions
from fabriclib.radius.remove_radius_client import remove_radius_client
from fabriclib.radius.rotate_radius_secret import rotate_radius_secret
from fabriclib.radius.set_radius_client import set_radius_client
from fabriclib.radius.unmap_radius_group import unmap_radius_group
from fabriclib.system.apply_changes import apply_changes

USAGE = """usage: fabricctl radius status                     server name, RADIUS clients, groups that may join
                                                   by password
       fabricctl radius log [-n N]                 recent 802.1X decisions (accepted, refused and why)
       fabricctl radius add-client <name> <address> [--vendor unifi|cisco|generic] [--transport udp|radsec]
                                   [--secret-prompt] [--no-message-authenticator] [--no-apply]
       fabricctl radius set-client <name> [--vendor unifi|cisco|generic] [--transport udp|radsec] [--no-apply]
       fabricctl radius sessions                   open 802.1X sessions (from accounting) and what can be done to them
       fabricctl radius disconnect <client> <session>              end a session (CoA, the vendors that have it)
       fabricctl radius reauthenticate <client> <session> [--bounce]   authenticate it again (--bounce: and re-DHCP)
       fabricctl radius rotate-secret <name> [--secret-prompt] [--no-apply]
       fabricctl radius remove-client <name> [--no-apply]
       fabricctl radius map-group <group> [--vlan N] [--priority N] [--no-apply]   members may join by password
       fabricctl radius unmap-group <group> [--no-apply]
  A new secret is shown once; --secret-prompt keeps one the switch already has (typed, hidden).
  Vendors and what each supports (RadSec, CoA): manual 1.11.1.2."""


def _apply(args):
    """Purpose: Apply a just-recorded 802.1X change now, unless --no-apply was given.
    Inputs:  args — list of str (looks for "--no-apply"). Runs apply_changes as root (interactive.py --apply).
    Returns: 0 if skipped or applied; 1 if apply failed (last 2000 characters of its output on stdout).
    Fails:   subprocess.TimeoutExpired (900 s) and OSError from apply_changes propagate.
    Feeds:   run_radius_command (add-client, rotate-secret, remove-client, map-group, unmap-group).
    """
    if "--no-apply" in args:
        print("recorded; apply with: sudo fabricctl --apply")
        return 0
    ok, output = apply_changes("root", "cli")
    print("applied (FreeRADIUS restarted)" if ok else output[-2000:])
    return 0 if ok else 1


def _secret(args):
    """Purpose: An existing shared secret typed at a hidden prompt, never taken from argv.
    Inputs:  args — list of str (looks for "--secret-prompt").
    Returns: the stripped secret (str), or None without --secret-prompt.
    Fails:   EOFError / KeyboardInterrupt from getpass propagate.
    Feeds:   run_radius_command (add-client, rotate-secret).
    """
    return ask_secret("radius.secret", "shared secret (hidden): ").strip() if "--secret-prompt" in args else None


def run_radius_command(v, argv):
    """Purpose: `fabricctl radius status | log | add-client | set-client | rotate-secret | remove-client | map-group |
             unmap-group | sessions | disconnect | reauthenticate` —
             the FreeRADIUS tab's operations without the web UI.
    Inputs:  v — the rendered vars (SetupContext.load_state().vars).
             argv — list of str after "radius" (default status); options -n N, --vlan N, --priority N, --secret-prompt,
             --no-message-authenticator, --vendor V, --transport T, --bounce, --no-apply.
    Returns: exit status: 0 success; 1 a ValidationError or a failed apply; 2 usage (printed to stderr).
    Fails:   ValidationError is caught (exit 1: a refused CoA says why); a non-numeric -n (ValueError), an option given
             last without its value (IndexError) and journalctl errors in `log` propagate.
    Feeds:   fabriclib/cli.py (`fabricctl radius`).
    Notes:   a new secret is printed once; an existing one is typed at a hidden prompt, never passed in argv.
    """
    cmd, args = (argv[0], argv[1:]) if argv else ("status", [])
    pos = [a for i, a in enumerate(args) if not a.startswith("-")
           and (i == 0 or args[i - 1] not in ("--vlan", "--priority", "-n", "--vendor", "--transport"))]
    opt = {k: args[args.index(f"--{k}") + 1] for k in ("vendor", "transport") if f"--{k}" in args}
    try:
        if cmd == "status" and not pos:
            o = radius_overview(v, log_limit=0)
            if not o["enabled"]:
                print("802.1X is off (install_freeradius: false)")
                return 0
            print(f"server name (supplicants check it): {o['server_name']}   RADIUS on {o['host_ip']}:1812/udp")
            for c in o["clients"] or []:
                print(f"  {c['name']:<16} {c['address']:<20} {c['vendor']:<8} "
                      + ("RadSec (TCP 2083)" if c["transport"] == "radsec" else "RADIUS/UDP (relaxed: MD5 only)")
                      + "  Message-Authenticator " + ("required" if c["message_authenticator"] else "NOT required"))
            if not o["clients"]:
                print("  no RADIUS clients yet: fabricctl radius add-client <name> <address>")
            print("people who may join by password (EAP-TTLS):")
            for m in o["people"] or []:
                print(f"  group {m['group']:<20} vlan {m['vlan'] or '-':<5} priority {m['priority']}")
            if not o["people"]:
                print("  nobody: fabricctl radius map-group <group> [--vlan N]")
            return 0
        if cmd == "log":
            n = int(args[args.index("-n") + 1]) if "-n" in args else 50
            for e in list_auth_log(n):
                print(f"{e['time']}  {e['decision']:<6} {e['method']:<8} {e['device']:<16} vlan {e['vlan']:<5} "
                      f"mac {e['mac']:<17} via {e['nas']}" + (f"  — {e['reason']}" if e["reason"] else ""))
            return 0
        if cmd == "sessions" and not pos:
            o = radius_sessions(v)
            if o["error"]:
                print(o["error"], file=sys.stderr)
                return 1
            for e in o["sessions"]:
                print(f"{e['client']:<12} {e['session']:<24} {e['who']:<16} mac {e['mac']:<17} vlan {e['vlan']:<5} "
                      f"port {e['port']:<12} seen {e['seen']}  "
                      + (", ".join(e["actions"]) if e["actions"] else "no CoA"))
            if not o["sessions"]:
                print("no open sessions (switches must send accounting: manual 4.11.1)")
            return 0
        if cmd in ("disconnect", "reauthenticate") and len(pos) == 2:
            action = "disconnect" if cmd == "disconnect" else "bounce" if "--bounce" in args else "reauthenticate"
            print(coa_session(v, "root", action, pos[0], pos[1])["message"])
            return 0
        if cmd == "set-client" and len(pos) == 1:
            c = set_radius_client("root", pos[0], opt.get("vendor"), opt.get("transport"))
            print(f"RADIUS client {c['name']}: vendor {c['vendor']}, transport {c['transport']}")
            return _apply(args)
        if cmd == "add-client" and len(pos) == 2:
            secret = add_radius_client("root", pos[0], pos[1], "--no-message-authenticator" not in args, _secret(args),
                                       vendor=opt.get("vendor", "generic"), transport=opt.get("transport", "udp"))
            print(f"RADIUS client {pos[0].lower()} added; its shared secret (shown once, kept in OpenBao):\n{secret}")
            return _apply(args)
        if cmd == "rotate-secret" and len(pos) == 1:
            secret = rotate_radius_secret("root", pos[0], _secret(args))
            print(f"new shared secret for {pos[0].lower()} (shown once; give the device the same):\n{secret}")
            return _apply(args)
        if cmd == "map-group" and len(pos) == 1:
            opt = {k: args[args.index(f"--{k}") + 1] for k in ("vlan", "priority") if f"--{k}" in args}
            m = map_radius_group("root", pos[0], opt.get("vlan"), opt.get("priority", 100))
            print(f"members of {m['group']} may join by password" + (f" on VLAN {m['vlan']}" if m["vlan"] else ""))
            return _apply(args)
        if cmd == "unmap-group" and len(pos) == 1:
            unmap_radius_group("root", pos[0])
            print(f"members of {pos[0]} may no longer join by password")
            return _apply(args)
        if cmd == "remove-client" and len(pos) == 1:
            remove_radius_client("root", pos[0])
            print(f"RADIUS client {pos[0].lower()} removed")
            return _apply(args)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
