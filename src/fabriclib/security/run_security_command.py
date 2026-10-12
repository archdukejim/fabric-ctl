import argparse
import os
import subprocess
import sys
import time

from fabriclib.common.ask import ask
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import VARS_FILE
from fabriclib.security.apply_signin import apply_signin
from fabriclib.security.set_signin_layer import set_signin_layer
from fabriclib.security.signin_layers import LAYERS, read_lowered, signin_rows

USAGE = """usage: fabricctl security                         the sign-in layers and their values
       fabricctl security raise <layer> [<value>]
                                                  raise a layer (the web console's Security page does the same)
       fabricctl security lower <layer> [<value>]
                                                  lower a layer (asks for the layer's name; audited)
       fabricctl security kerberos on|off         signing in with the domain logon"""


def _actor():
    """Purpose: who changes a layer from the host, for the audit log: root, and the account that ran sudo.
    Inputs:  env SUDO_USER.
    Returns: str ("root" or "root (sudo by <user>)").
    Fails:   never.
    Feeds:   run_security_command."""
    who = os.environ.get("SUDO_USER")
    return f"root (sudo by {who})" if who and who != "root" else "root"


def _confirm(layer, row, new):
    """Purpose: the typed confirmation before a lowering (2.1.6.24): what is lost, then the layer's name typed back.
    Inputs:  layer — a LAYERS key; row — its signin_rows entry; new — the lower value as shown.
    Returns: bool, whether the name was typed back exactly.
    Fails:   EOFError when stdin closes.
    Feeds:   run_security_command (lower)."""
    print(f"Lowering {layer}: {row['what']}\n  now: {row['value']}   after: {new}\n"
          "Every sign-in this covers is weaker from now on. The change is recorded in the audit log, and doctor and "
          "the web console show a warning until it is raised again.")
    return ask("security.lower.confirm", f"Type the layer's name ({layer}) to lower it: ") == layer


def run_security_command(argv, vars_file=VARS_FILE):
    """Purpose: `fabricctl security` — the sign-in layers (manual 2.3.6.2.6.4, 2.1.6.24): status; raise a layer (also
             the web console's Security page); lower one, only here on the host, after its name is typed back (--yes
             does not skip it, and it refuses without a terminal); Kerberos on or off. Only routes to the security/
             units and prints.
    Inputs:  argv — list of str after "security": none (status) | raise <layer> [<value>] | lower <layer> [<value>] |
             kerberos on|off; --yes is refused for lower. vars_file — the install's vars.yaml (tests: a scratch one).
             A missing value raises to the next level up or on, and lowers to none or off.
    Returns: exit status: 0 done (or nothing to change); 1 refused or the apply failed ("error: …" on stderr); 2 a
             lowering not confirmed.
    Fails:   SystemExit 2 from argparse; OSError / yaml errors from the vars, lowered or audit files; whatever
             apply_signin raises (subprocess.TimeoutExpired).
    Feeds:   fabriclib/cli.py (`fabricctl security`)."""
    ap = argparse.ArgumentParser(prog="fabricctl security")
    sub = ap.add_subparsers(dest="cmd")
    for name, text in (("raise", "raise a layer (the web console's Security page does the same)"),
                       ("lower", "lower a layer (asks for the layer's name; audited; shown until raised again)")):
        p = sub.add_parser(name, help=text)
        p.add_argument("layer", choices=sorted(LAYERS))
        p.add_argument("value", nargs="?")
        p.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
    k = sub.add_parser("kerberos", help="signing in with the domain logon: on or off")
    k.add_argument("value", choices=["on", "off"])
    ap.usage = USAGE.removeprefix("usage: ")    # after the subparsers: they take their prog from it
    args = ap.parse_args(argv)
    config_dir = os.path.dirname(vars_file)
    rows = {r["layer"]: r for r in signin_rows(load_vars(vars_file), read_lowered(config_dir))}

    if not args.cmd:
        for r in rows.values():
            shown = r["value"] + (f" (the admin tools ask for {r['effective']})"
                                  if r["layer"] == "admin-2fa" and r["effective"] != r["value"] else "")
            flag = (f"   ! lowered from {r['lowered']['from']} by {r['lowered']['by']}, {r['lowered']['at']}"
                    if r["lowered"] else "")
            print(f"{r['layer']:<14} {shown:<36} {r['what']}{flag}")
        print("\nRaise: the web console's Security page, or sudo fabricctl security raise <layer> [<value>]\n"
              "Lower: sudo fabricctl security lower <layer> [<value>] (asks for the layer's name)")
        return 0
    try:
        if args.cmd == "kerberos":
            res = set_signin_layer(_actor(), "kerberos", args.value, "cli", vars_file=vars_file)
        elif args.cmd == "raise":
            value = args.value or (rows[args.layer]["choices"] or [rows[args.layer]["value"]])[0]
            res = set_signin_layer(_actor(), args.layer, value, "cli", vars_file=vars_file)
        else:
            if args.yes:
                print("error: a lowering is confirmed by typing the layer's name, never by --yes", file=sys.stderr)
                return 1
            if not sys.stdin.isatty():
                print("error: a lowering needs a terminal (it asks for the layer's name)", file=sys.stderr)
                return 1
            value = args.value or ("none" if LAYERS[args.layer]["kind"] == "level" else "off")
            if not _confirm(args.layer, rows[args.layer], value):
                print("not lowered: the name was not typed back", file=sys.stderr)
                return 2
            res = set_signin_layer(_actor(), args.layer, value, "cli", lower=True, vars_file=vars_file)
    except ValidationError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not res["changed"]:
        print(f"{res['layer']} is {res['to']} already: nothing to change")
        return 0
    print(f"{res['layer']}: {res['from']} -> {res['to']}; applying…")
    before = _web_started()
    ok, out = apply_signin(_actor(), "cli")
    if not ok:
        print(out[-3000:], file=sys.stderr)
        print("error: the setting is saved but did not apply; fix the cause and run sudo fabricctl --apply, then "
              "sudo fabricctl --keycloak-sync", file=sys.stderr)
        return 1
    if "Restarting webui" in out:              # the apply queued the web console's restart: wait for it
        _wait_web(before)
    print("done: Keycloak and the web console use it now")
    return 0


def _web_started():
    """Purpose: when the web console's unit last became active (systemd's monotonic clock).
    Inputs:  none.
    Returns: str ("" when systemctl or the unit is missing).
    Fails:   never.
    Feeds:   run_security_command."""
    res = subprocess.run(["systemctl", "show", "fabric-web", "-p", "ActiveEnterTimestampMonotonic", "--value"],
                         capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 else ""


def _wait_web(before, timeout=180):
    """Purpose: after an apply that queued a restart of the web console (`systemctl restart --no-block`), wait until
             it has started again, so "done" means it answers.
    Inputs:  before — _web_started() from before the apply; timeout — seconds.
    Returns: None (gives up quietly after timeout: doctor shows a web console that did not come back).
    Fails:   never.
    Feeds:   run_security_command."""
    end = time.time() + timeout
    while time.time() < end:
        state = subprocess.run(["systemctl", "is-active", "fabric-web"], capture_output=True, text=True).stdout
        if state.strip() == "active" and _web_started() not in ("", before):
            return
        time.sleep(2)
