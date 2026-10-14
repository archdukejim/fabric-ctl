import datetime
import os
import sys

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import VARS_FILE
from fabriclib.federation.change_dc_type import change_dc_type
from fabriclib.federation.confirm_plan import confirm_plan
from fabriclib.federation.create_invitation import create_invitation
from fabriclib.federation.federation_status import federation_status
from fabriclib.federation.drop_relay import drop_relay
from fabriclib.federation.list_invitations import list_invitations
from fabriclib.federation.read_change_token import read_change_token
from fabriclib.federation.remove_site import remove_site
from fabriclib.federation.request_dc_type import request_dc_type
from fabriclib.federation.rodc_lost import rodc_lost
from fabriclib.federation.reparent_site import reparent_site
from fabriclib.federation.revoke_invitation import revoke_invitation
from fabriclib.federation.show_networks import show_networks
from fabriclib.federation.set_federation_endpoint import set_federation_endpoint
from fabriclib.setup.errors import SetupError
from fabriclib.system.apply_changes import apply_changes
from fabriclib.setup.read_join_invitation import read_join_invitation

USAGE = """usage: fabricctl federation status                 this install's place in its fabric: upstream, sites,
                                                   invitations
       fabricctl federation enable | disable       the endpoint sites join through (https://federation.<domain>)
       fabricctl federation invite <site> [--nest N] [--via NODE] [--dc writable|rodc]
                                                   a one-time invitation for a new site (good for one hour); on the
                                                   root it attaches flat, on a site nested under it; --nest N lets
                                                   it hold N levels of sites below it; --via NODE: it joins (and
                                                   talks) through that site, which only relays; --dc: the site's
                                                   domain controller joins writable (default) or read-only
       fabricctl federation relay direct           on a site: stop using its relay node, talk to the upstream
       fabricctl federation invitations            open invitations (and DC type change tokens)
       fabricctl federation dc-type <site> writable|rodc
                                                   from a site above: ask for that site's DC to change type; prints
                                                   a one-time change token (one hour) for the site's admin
       fabricctl federation rodc-lost <site>       from a site above, at a writable DC: that site's read-only DC
                                                   is lost or stolen: list every account whose password it held,
                                                   then (the site's name typed) reset them and remove the DC
       fabricctl federation dc-type show           at the site: the change asked for, and what accepting it does
       fabricctl federation dc-type accept [@FILE|-] [--yes]
                                                   at the site: carry the change out (the token at the prompt, from
                                                   a file or stdin; consent typed, or --yes); run again to go on
       fabricctl federation networks               the address plan: every site's networks, VLANs, notes, overlaps
       fabricctl federation remove <site>          forget a site that joined here (its CA revoked)
       fabricctl federation reparent [@FILE|-]     on a site: move under the parent whose invitation you paste
       fabricctl federation revoke <id|site>       withdraw an open invitation
  On the new site: sudo fabricctl setup --join   (a fresh install; paste the invitation at the prompt)"""


def _when(epoch):
    """Purpose: an epoch as local date and time to the minute.
    Inputs:  epoch — int seconds.
    Returns: str "YYYY-MM-DD HH:MM".
    Fails:   never for an int.
    Feeds:   run_federation_command (invite, invitations, status)."""
    return datetime.datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M")


def _show_accounts(plan):
    """Purpose: print every account a lost read-only DC held the password of, and what happens to each.
    Inputs:  plan � plan_rodc_lost's answer.
    Returns: True (so it chains before the confirmation).
    Fails:   never.
    Feeds:   run_federation_command (rodc-lost)."""
    print(f"read-only DC(s): {', '.join(plan['rodcs']) or 'none left'}; {len(plan['accounts'])} account(s) revealed:")
    left = {a["dn"].lower() for a in plan["reset_left"]}
    for a in plan["accounts"]:
        what = "reset" if a["dn"].lower() in left else next((s["why"] for s in plan["skipped"]
                                                              if s["dn"] == a["dn"]), "reset already")
        print(f"  {a['kind']:<9} {a.get('name') or '-':<24} {what}  ({a['dn']})")
    return True


def run_federation_command(ctx, argv):
    """Purpose: `fabricctl federation status | enable | disable | invite | invitations | revoke | remove | reparent |
             relay | networks | dc-type | rodc-lost` —
             joining sites to
             this install without the web UI (manual 1.9.4.1).
    Inputs:  ctx — SetupContext with state loaded (ctx.vars: the rendered vars); argv — list of str after
             "federation" (default status).
    Returns: exit status: 0 success; 1 a ValidationError or a failed apply; 2 usage (printed to stderr).
    Fails:   ValidationError is caught (exit 1); OSError and errors from set_federation_endpoint other than
             ValidationError propagate.
    Feeds:   fabriclib/cli.py (`fabricctl federation`).
    Notes:   an invitation's secret is printed once, never logged; the actor is root (the CLI runs as root)."""
    cmd, args = (argv[0], argv[1:]) if argv else ("status", [])
    v = ctx.vars
    try:
        if cmd == "status" and not args:
            s = federation_status(v)
            print(f"site {s['site_name']}  domain {s['domain']}  organisation {s['org_domain']}  role {s['role']}")
            print(f"federation endpoint: {'on, https://' + s['endpoint_host'] if s['endpoint'] else 'off'}")
            if s["upstream"]:
                u = s["upstream"]
                print(f"upstream: {u.get('site_name')} ({u.get('domain')}, {u.get('address')}), "
                      f"joined {u.get('joined')}"
                      + (f", through relay {u['relay'].get('site')}" if u.get("relay") else ""))
            for name, site in sorted(s["sites"].items()):
                print(f"  site {name:<16} {site.get('domain', ''):<28} {site.get('address', ''):<16} "
                      f"joined {site.get('joined', '')}  CA until {site.get('ca_not_after', '')}")
            if not s["sites"] and s["role"] != "site":
                print("  no sites yet" + ("" if s["endpoint"] else ": fabricctl federation enable, then invite <site>"))
            for i in s["invitations"]:
                print(f"  invitation {i['id']} for {i['site']}, open until {_when(i['expires'])}")
            return 0
        if cmd in ("enable", "disable") and not args:
            ok, output = set_federation_endpoint(ctx, "root", cmd == "enable")
            print(output[-2000:] if not ok else
                  f"federation endpoint {'on' if cmd == 'enable' else 'off'}"
                  + (f": https://{v.get('hostname_federation')}" if cmd == "enable" else " (sites that joined stay)"))
            return 0 if ok else 1
        opts = dict(zip(args[1::2], args[2::2])) if cmd == "invite" and args and len(args) % 2 == 1 else None
        if cmd == "invite" and opts is not None and set(opts) <= {"--nest", "--via", "--dc"} \
                and opts.get("--nest", "0").isdigit():
            inv = create_invitation(v, "root", args[0], nest=int(opts.get("--nest", 0)), via=opts.get("--via", ""),
                                    dc=opts.get("--dc", "writable"))
            how = (f"nested under {v.get('site_name')}" if inv["nested"] else "flat, under the root site") \
                + (f", through {inv['via']}" if inv["via"] else "")
            print(f"Invitation for site {inv['site']} ({how}; may hold {inv['nest']} level(s) of sites below it; "
                  f"one use, until {_when(inv['expires'])}):\n")
            print(f"  {inv['invitation']}\n")
            print("On the new site run `sudo fabricctl setup --join` and paste it at the prompt (or save it to a\n"
                  "file and use --join @FILE). It carries a secret: send it over a channel you trust and never put\n"
                  f"it on a command line. Withdraw it with: fabricctl federation revoke {inv['id']}")
            return 0
        if cmd == "dc-type" and len(args) == 2 and args[0] not in ("show", "accept"):
            req = request_dc_type(v, "root", args[0], args[1])
            print(f"Site {req['site']}'s DC ({req['was']}) is asked to become {req['to']}. Change token (one use, "
                  f"until {_when(req['expires'])}):\n\n  {req['token']}\n")
            print(f"On {req['site']} run `sudo fabricctl federation dc-type accept` and paste it at the prompt. It "
                  "carries a secret: send it over a channel you trust and never put it on a command line. Withdraw "
                  f"it with: fabricctl federation revoke {req['id']}")
            return 0
        if cmd == "rodc-lost" and len(args) == 1:
            site = args[0].strip().lower()
            res = rodc_lost(v, os.path.dirname(VARS_FILE), "root", site,
                            confirmed=lambda plan: _show_accounts(plan) and confirm_plan(plan["lines"], site))
            print("\n".join(res["plan"]["lines"]) if not res["changed"] else
                  f"done: {len(res['reset'])} account(s) reset, read-only DC(s) removed: "
                  f"{', '.join(res['removed']) or 'none left'}; the record: config/rodc-lost-{site}.json")
            return 0
        if cmd == "dc-type" and args == ["show"]:
            plan = change_dc_type(v, os.path.dirname(VARS_FILE), "root")["plan"]
            print(f"requested: this site's DC becomes {plan['to']}")
            for n, line in enumerate(plan["lines"], 1):
                print(f"  {n}. {line}")
            return 0
        if cmd == "dc-type" and args[:1] == ["accept"] and len(args) <= 3 and \
                all(a == "--yes" or a == "-" or a.startswith("@") for a in args[1:]):
            source = next((a for a in args[1:] if a != "--yes"), "")
            res = change_dc_type(v, os.path.dirname(VARS_FILE), "root", token_text=read_change_token(source),
                                 consent=lambda lines: confirm_plan(lines, "yes", yes="--yes" in args))
            print(f"done: this site's DC is {res['plan']['to']} (steps this run: {', '.join(res['done']) or 'none'})")
            return 0
        if cmd == "invitations" and not args:
            rows = list_invitations(v)
            for i in rows:
                print(f"{i['id']}  site {i['site']:<16} open until {_when(i['expires'])}  by {i['actor']}"
                      + ("  (DC type change)" if i.get("kind") == "dc-type" else ""))
            if not rows:
                print("no open invitations")
            return 0
        if cmd == "networks" and not args:
            try:
                return 1 if show_networks(v) else 0
            except RuntimeError as e:                # the directory answered with an error
                print(f"error: {e}", file=sys.stderr)
                return 1
        if cmd == "relay" and args == ["direct"]:
            relay = drop_relay("root")
            print(f"relay {relay.get('site')} dropped: this site talks to its upstream directly")
            return 0
        if cmd == "remove" and len(args) == 1:
            gone = remove_site("root", args[0], v=v)
            ok, output = apply_changes("root", "cli")
            print(f"{args[0]} removed (its delegation and secondary zone too); {gone['revoked'] or 'it had no CA'}"
                  if ok else output[-2000:])
            return 0 if ok else 1
        if cmd == "reparent" and len(args) <= 1:
            res = reparent_site(ctx, "root", read_join_invitation(args[0] if args else ""))
            print(f"now under {res['parent']} ({res['site_ca_depth']} CA(s) between this site's CA and the root); "
                  "service certificates re-issued. Re-issue people's web UI certificates: fabricctl client-cert <user>")
            if not res["applied"]:
                print(res["output"])
            return 0 if res["applied"] else 1
        if cmd == "revoke" and len(args) == 1:
            print(f"withdrawn: {revoke_invitation(v, 'root', args[0])} invitation(s)")
            return 0
    except (ValidationError, SetupError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
