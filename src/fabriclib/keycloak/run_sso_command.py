import argparse
import getpass
import sys

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.keycloak.add_app_client import add_app_client
from fabriclib.keycloak.keycloak_admin import keycloak_admin
from fabriclib.keycloak.list_app_clients import list_app_clients
from fabriclib.keycloak.remove_app_client import remove_app_client
from fabriclib.secrets.load_secrets import load_secrets

USAGE = """usage: fabricctl sso add <name> --redirect URL (repeatable)
                                                  register an app; prints its client id and secret once
       fabricctl sso list                         the registered apps
       fabricctl sso remove <name>                unregister an app"""


def run_sso_command(argv):
    """Purpose: `fabricctl sso add | list | remove` — apps (Proxmox VE, TrueNAS, …) signing people in through this
             site's Keycloak (manual 4.6.2): only routes to the keycloak/ units and prints.
    Inputs:  argv — list of str after "sso". add: name, --redirect URL (repeatable).
    Returns: exit status: 0 done; 1 refused ("error: …" on stderr).
    Fails:   SystemExit 2 from argparse on bad arguments; SystemExit from the Keycloak admin client (Keycloak down,
             its admin sign-in refused); other exceptions propagate.
    Feeds:   fabriclib/cli.py (`fabricctl sso`).
    Notes:   the client secret is printed once and kept nowhere by fabric; adding and removing are audited
             (SSO_APP_ADD, SSO_APP_REMOVE)."""
    ap = argparse.ArgumentParser(prog="fabricctl sso")
    sub = ap.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="register an app; prints its client id and secret once")
    add.add_argument("name")
    add.add_argument("--redirect", action="append", default=[], help="the app's redirect URL (repeatable)")
    sub.add_parser("list", help="the registered apps")
    rem = sub.add_parser("remove", help="unregister an app")
    rem.add_argument("name")
    ap.usage = USAGE.removeprefix("usage: ")    # after the subparsers: they take their prog from it
    args = ap.parse_args(argv)
    v = load_vars()
    if not v.get("install_keycloak"):
        print("error: single sign-on needs Keycloak (install_keycloak: true)", file=sys.stderr)
        return 1
    kc, realm = keycloak_admin(v, load_secrets(v=v))
    actor = getpass.getuser()
    try:
        if args.cmd == "add":
            app = add_app_client(kc, realm, v, args.name, args.redirect)
            write_audit(actor, "SSO_APP_ADD", f"app={app['client_id']} redirects={','.join(args.redirect)}", "cli")
            print(f"client id:     {app['client_id']}\nclient secret: {app['secret']}   (shown once: copy it now)\n"
                  f"issuer:        {app['issuer']}\ndiscovery:     {app['discovery']}\n"
                  "groups claim:  groups (the person's domain groups, to map to the app's roles)")
        elif args.cmd == "list":
            apps = list_app_clients(kc, realm)
            for a in apps:
                print(f"{a['name']:<20} {a['client_id']:<24} {' '.join(a['redirects'])}")
            if not apps:
                print("no apps registered (fabricctl sso add <name> --redirect https://…)")
        else:
            gone = remove_app_client(kc, realm, args.name)
            write_audit(actor, "SSO_APP_REMOVE", f"app={gone}", "cli")
            print(f"{gone} removed: the app can no longer sign people in")
    except ValidationError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0
