import sys

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.common.apply_dhcp_change import apply_dhcp_change
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.ipam.add_address import add_address
from fabriclib.ipam.add_range import add_range
from fabriclib.ipam.add_subnet import add_subnet
from fabriclib.ipam.add_vlan import add_vlan
from fabriclib.ipam.common.fields import KEEP
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.export_plan import export_plan
from fabriclib.ipam.find_in_plan import find_in_plan
from fabriclib.ipam.offer_reservations import offer_reservations
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.options.run_option_command import run_option_command
from fabriclib.ipam.remove_address import remove_address
from fabriclib.ipam.remove_range import remove_range
from fabriclib.ipam.remove_subnet import remove_subnet
from fabriclib.ipam.remove_vlan import remove_vlan
from fabriclib.ipam.set_address import set_address
from fabriclib.ipam.set_block import set_block
from fabriclib.ipam.set_subnet import set_subnet
from fabriclib.ipam.scan_subnet import scan_subnet
from fabriclib.ipam.scanpolicy.run_scan_policy_command import run_scan_policy_command
from fabriclib.ipam.set_vlan import set_vlan
from fabriclib.ipam.show_plan import show_plan
from fabriclib.ipam.show_scan import show_scan
from fabriclib.ipam.suggestions import suggest_block
from fabriclib.ipam.sync.sync_plan import sync_plan

USAGE = """usage: fabricctl ipam show [<site>]                    a site's VLANs, subnets, ranges, addresses, leases
       fabricctl ipam find <ip|name|mac>               where an address, a name or a MAC is, in every site
       fabricctl ipam export [<site>]                  the address table as CSV (every site without one)
       fabricctl ipam block [<n>]                      the site's number (1-255): shown, or set
       fabricctl ipam vlan add <id> --name N [--subnet CIDR | --no-subnet] [--gateway IP] [--purpose T]
                               [--notes T] [--access full|guest] [--dhcp on|off] [--relay IP] [--no-split]
                               [--allow-overlap "<why>"]
       fabricctl ipam vlan set <id> [--name N] [--purpose T] [--notes T] [--access full|guest]
                               [--gateway IP|none] [--dhcp on|off] [--relay IP|none] [--allow-overlap "<why>"|none]
       fabricctl ipam vlan remove <id> [--force]
       fabricctl ipam subnet add <vlan> <cidr> [--name N] [--gateway IP] [--dhcp on|off] [--relay IP] [--notes T]
                               [--no-split] [--allow-overlap "<why>"]
       fabricctl ipam subnet set <name|cidr> [--gateway IP|none] [--dhcp on|off] [--relay IP|none] [--notes T]
                               [--allow-overlap "<why>"|none]
       fabricctl ipam subnet remove <name|cidr> [--force]
       fabricctl ipam range add <vlan> gateway|static|dhcp|reserved <first> <last> [--notes T]
       fabricctl ipam range remove <vlan> <first>
       fabricctl ipam address add <ip> --kind static|reservation|infrastructure [--name N] [--mac M]
                               [--owner T] [--notes T] [--dns on|off] [--vlan V]
       fabricctl ipam address set <ip> [--kind K] [--name N|none] [--mac M|none] [--owner T] [--notes T]
                               [--dns on|off]
       fabricctl ipam address remove <ip>
       fabricctl ipam scan <subnet> [--no-ask]         which addresses answer, and which nobody recorded: offers to
                                                       record each (a subnet of this site's plan; name or network)
       fabricctl ipam scan-policy …                    whether scans may run, set like a group policy
                                                       (fabricctl ipam scan-policy --help)
       fabricctl ipam sync                             Sync now: the plan poll at once, and BIND's records when DNS
                                                       waits (never an apply; only Kea restarts)
       fabricctl ipam option|class|netboot|option-editors|watch …   DHCP options, netboot, the plan poll
                               (fabricctl ipam option --help)
   --site S: another site's plan (a site above it may edit it); a change to this site's plan applies at once
   unless --no-apply"""
FLAGS = {"--site", "--name", "--subnet", "--gateway", "--purpose", "--notes", "--access", "--dhcp", "--relay",
         "--allow-overlap", "--kind", "--mac", "--owner", "--dns", "--vlan"}
BARE = {"--no-subnet", "--no-split", "--force", "--no-apply", "--no-ask"}


def _parse(args):
    """Purpose: split command arguments into positionals, --flag values (the last one counts) and bare flags.
    Inputs:  args — list of str.
    Returns: (positionals, {flag: value}, set of bare flags).
    Fails:   ValidationError for a value flag without a value, or a flag `fabricctl ipam` does not know.
    Feeds:   run_ipam_command."""
    pos, vals, bare, i = [], {}, set(), 0
    while i < len(args):
        a = args[i]
        if a in FLAGS:
            if i + 1 >= len(args):
                raise ValidationError(f"{a} needs a value")
            vals[a] = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            if a not in BARE:
                raise ValidationError(f"unknown option {a}")
            bare.add(a)
        else:
            pos.append(a)
        i += 1
    return pos, vals, bare


def _on_off(text, flag):
    """Purpose: an on|off flag's value.
    Inputs:  text — str; flag — its name, for the message.
    Returns: bool.
    Fails:   ValidationError for anything but on or off.
    Feeds:   run_ipam_command."""
    if str(text).lower() not in ("on", "off"):
        raise ValidationError(f"{flag} is on or off")
    return str(text).lower() == "on"


def _keep(vals, flag, clear=False, convert=None):
    """Purpose: a set command's value: KEEP when the flag is absent; "" for "none" where it clears the field.
    Inputs:  vals — parsed flags; flag — e.g. "--gateway"; clear — whether "none" clears it; convert — function for
             the value (e.g. on/off), or None.
    Returns: KEEP, "" or the value.
    Fails:   what convert raises.
    Feeds:   run_ipam_command (vlan set, subnet set, address set)."""
    if flag not in vals:
        return KEEP
    if clear and vals[flag].lower() == "none":
        return ""
    return convert(vals[flag], flag) if convert else vals[flag]


def _leases(v, site):
    """Purpose: this site's live leases for show, find and export; none for another site or with DHCP off.
    Inputs:  v — fabric vars (install_kea, site_name); site — the site shown ("" this one).
    Returns: list_leases' rows, or None (DHCP off, another site, Kea not answering).
    Fails:   never: a Kea error leaves the leases out.
    Feeds:   run_ipam_command."""
    if not v.get("install_kea") or (site and site != v.get("site_name")):
        return None
    try:
        return list_leases(v)
    except (ValidationError, OSError, ValueError, TypeError):
        return None


def _print_rows(rows):
    """Purpose: print find's rows, one line each.
    Inputs:  rows — find_in_plan's rows.
    Returns: None.
    Fails:   never.
    Feeds:   run_ipam_command (find)."""
    for r in rows:
        print(f"{r['site']:<10} VLAN {str(r['vlan']):<5} {r['subnet']:<18} {r['ip']:<15} {r['kind']:<14} "
              f"{r['name']:<16} {r['mac']}" + (f"  ({r['range']} range)" if r["range"] else ""))


def _done(v, out, bare):
    """Purpose: report a change: its warnings, then apply it when it is this site's plan.
    Inputs:  v — fabric vars; out — edit_plan's result; bare — the bare flags given (--no-apply).
    Returns: exit status (apply_dhcp_change's for this site, 0 for another).
    Fails:   what apply_dhcp_change raises.
    Feeds:   run_ipam_command."""
    for w in out["warnings"]:
        print(f"warning: {w}")
    if out["site"] != v.get("site_name"):
        print(f"written to {out['site']}'s plan: it takes effect at that site's next apply")
        return 0
    return apply_dhcp_change(["--no-apply"] if "--no-apply" in bare else [])


def _subnet_line(out):
    """Purpose: what `vlan add` and `subnet add` print for the subnet they added and its ranges.
    Inputs:  out — add_vlan's or add_subnet's result (subnet, ranges).
    Returns: list of str.
    Fails:   never.
    Feeds:   run_ipam_command."""
    sub = out["subnet"]
    return ([f"  subnet {sub['name']}: {sub['cidr']}, gateway {sub['gateway'] or '-'}"] if sub else []) + [
        f"  {rng['kind']} {rng['first']} - {rng['last']}" for rng in out["ranges"]]


def run_ipam_command(v, argv, secrets=None, container="samba"):
    """Purpose: `fabricctl ipam …` — the address manager's plan from the command line (manual 1.10.4.9, 1.10.4.16;
             Volume 4: 4.10.2): show, find and export, the site's number, and changes to VLANs, subnets (several
             per VLAN, 2.1.10.18), ranges and addresses, this site's or (--site) a site below it; a scan of one of
             this site's subnets, offering to record what nobody did (2.1.10.26); the DHCP options, netboot and the
             plan poll through run_option_command (1.10.4.24 to 1.10.4.26); the scan policy through
             run_scan_policy_command (1.10.4.27) and Sync now (sync_plan, 1.10.4.28). Routes only: every rule is in the
             function each command calls.
    Inputs:  v — the rendered vars (SetupContext.load_state().vars); argv — list of str after "ipam" (default
             show); secrets — fabric's secrets (default: loaded by the functions); container — the DC's container
             (tests name their own). See USAGE.
    Returns: exit status: 0 success (and help); 1 a refusal (ValidationError, printed with why) or a failed apply;
             2 usage (printed to stderr).
    Fails:   ValidationError is caught (exit 1); other exceptions propagate.
    Feeds:   fabriclib/cli.py (`fabricctl ipam`)."""
    if argv[:1] in (["--help"], ["-h"], ["help"]):
        print(USAGE)
        return 0
    cmd, args = (argv[0], argv[1:]) if argv else ("show", [])
    if cmd in ("option", "class", "netboot", "option-editors", "watch"):   # the options (1.10.4.24 to 1.10.4.26)
        return run_option_command(v, cmd, args, secrets, container)
    if cmd == "scan-policy":                                               # the scan policy (1.10.4.27)
        return run_scan_policy_command(v, args, secrets, container)
    common = {"secrets": secrets, "container": container}
    try:
        pos, vals, bare = _parse(args)
        site = vals.get("--site", "")
        if cmd == "show" and len(pos) <= 1 and not site:
            which = pos[0] if pos else v["site_name"]
            read = read_plan(v, secrets, of=which, container=container)
            sys.stdout.write(show_plan(read, which, _leases(v, which)))
            return 0
        if cmd == "find" and len(pos) == 1 and not site:
            read = read_plan(v, secrets, container=container)
            rows = find_in_plan(read, pos[0], _leases(v, ""), v["site_name"])
            if not rows:
                print(f"{pos[0]}: not in any site's plan")
                return 1
            _print_rows(rows)
            return 0
        if cmd == "export" and len(pos) <= 1 and not site:
            read = read_plan(v, secrets, of=pos[0] if pos else "", container=container)
            sys.stdout.write(export_plan(read, pos[0] if pos else "", _leases(v, pos[0] if pos else ""),
                                         v["site_name"]))
            return 0
        if cmd == "block" and not pos:
            which = site or v["site_name"]
            read = read_plan(v, secrets, of=which, container=container)
            plan = site_plan(read, which)
            print(f"site {which}  number " + (str(plan["block"]) if plan["block"] else
                                              f"none (suggested {suggest_block(read['sites'], which)})"))
            return 0
        if cmd == "block" and len(pos) == 1:
            out = set_block(v, "root", pos[0], site, **common)
            r = out["result"]
            print(f"site {out['site']} is number {r['block']}" + (f" (was {r['was']})" if r["was"] else "")
                  + ": what fabric suggests from now on is 10." + str(r["block"])
                  + ".<VLAN>.0/24; subnets already in the plan keep their networks")
            return 0
        if cmd == "sync" and not pos:                                      # Sync now (1.10.4.28)
            if site:
                raise ValidationError("a sync is this site's own: run it at that site")
            out = sync_plan(v, "root", container=container, secrets=secrets)
            print(f"plan poll: {out['state']}" + ("; Kea restarted" if out["kea_restarted"] else "; Kea unchanged")
                  + ("; firewall brought in line" if out["firewall"] else ""))
            print("DNS: " + (("published: " + (", ".join(out["dns"]["zones"]) or "nothing changed in the zones"))
                             if out["dns"] else "already in line with the plan"))
            return 0
        if cmd == "scan" and len(pos) == 1:
            if site:
                raise ValidationError("a scan covers only this site's own subnets: run it at that site")
            result = scan_subnet(v, "root", pos[0])
            sys.stdout.write(show_scan(result))
            if result["unrecorded"] and "--no-ask" not in bare and sys.stdin.isatty():
                if offer_reservations(v, result, **common):
                    return apply_dhcp_change(["--no-apply"] if "--no-apply" in bare else [])
            return 0
        sub, rest = (pos[0], pos[1:]) if pos else ("", [])
        if cmd == "vlan" and sub == "add" and len(rest) == 1 and "--name" in vals:
            if not rest[0].isdigit():
                raise ValidationError(f"VLAN ID {rest[0]!r} is a number from 1 to 4094")
            out = add_vlan(v, "root", int(rest[0]), vals["--name"], site, vals.get("--subnet", ""),
                           "--no-subnet" in bare, vals.get("--gateway", ""), vals.get("--purpose", ""),
                           vals.get("--notes", ""), vals.get("--access", "full"),
                           _on_off(vals["--dhcp"], "--dhcp") if "--dhcp" in vals else True, vals.get("--relay", ""),
                           vals.get("--allow-overlap", ""), "--no-split" not in bare, **common)
            r = out["result"]
            if r["block_set"]:
                print(f"site {out['site']} given the number {r['block_set']} (its order in the organisation)")
            print(f"VLAN {r['vlan']['id']} ({r['vlan']['name']}) added"
                  + (f": {r['subnet']['cidr']}, gateway {r['subnet']['gateway'] or '-'}" if r["subnet"] else ""))
            for rng in r["ranges"]:
                print(f"  {rng['kind']} {rng['first']} - {rng['last']}")
            return _done(v, out, bare)
        if cmd == "vlan" and sub == "set" and len(rest) == 1:
            out = set_vlan(v, "root", rest[0], site, name=_keep(vals, "--name"), purpose=_keep(vals, "--purpose"),
                           notes=_keep(vals, "--notes"), access=_keep(vals, "--access"),
                           gateway=_keep(vals, "--gateway", clear=True),
                           dhcp=_keep(vals, "--dhcp", convert=_on_off), relay=_keep(vals, "--relay", clear=True),
                           allow_overlap=_keep(vals, "--allow-overlap", clear=True), **common)
            print(f"VLAN {out['result']['vlan']['id']} changed")
            return _done(v, out, bare)
        if cmd == "vlan" and sub == "remove" and len(rest) == 1:
            out = remove_vlan(v, "root", rest[0], site, "--force" in bare, **common)
            print(f"VLAN {out['result']['vlan']['id']} removed"
                  + (f" with {out['result']['subnet']}" if out["result"]["subnet"] else ""))
            return _done(v, out, bare)
        if cmd == "subnet" and sub == "add" and len(rest) == 2:
            out = add_subnet(v, "root", rest[0], rest[1], site, vals.get("--name", ""), vals.get("--gateway", ""),
                             _on_off(vals["--dhcp"], "--dhcp") if "--dhcp" in vals else True, vals.get("--relay", ""),
                             vals.get("--notes", ""), vals.get("--allow-overlap", ""), "--no-split" not in bare,
                             **common)
            print(f"VLAN {out['result']['vlan']['id']} has a new subnet")
            print("\n".join(_subnet_line(out["result"])))
            return _done(v, out, bare)
        if cmd == "subnet" and sub == "set" and len(rest) == 1:
            out = set_subnet(v, "root", rest[0], site, gateway=_keep(vals, "--gateway", clear=True),
                             dhcp=_keep(vals, "--dhcp", convert=_on_off), relay=_keep(vals, "--relay", clear=True),
                             notes=_keep(vals, "--notes"), allow_overlap=_keep(vals, "--allow-overlap", clear=True),
                             **common)
            print(f"subnet {out['result']['name']} ({out['result']['cidr']}) changed")
            return _done(v, out, bare)
        if cmd == "subnet" and sub == "remove" and len(rest) == 1:
            out = remove_subnet(v, "root", rest[0], site, "--force" in bare, **common)
            s = out["result"]["subnet"]
            print(f"subnet {s['name']} ({s['cidr']}) removed" + (f" with {out['result']['addresses']} address(es)"
                                                                if out["result"]["addresses"] else ""))
            return _done(v, out, bare)
        if cmd == "range" and sub == "add" and len(rest) == 4:
            out = add_range(v, "root", rest[0], rest[1], rest[2], rest[3], site, vals.get("--notes", ""), **common)
            print(f"{out['result']['kind']} range {out['result']['first']} - {out['result']['last']} added")
            return _done(v, out, bare)
        if cmd == "range" and sub == "remove" and len(rest) == 2:
            out = remove_range(v, "root", rest[0], rest[1], site, **common)
            print(f"{out['result']['kind']} range {out['result']['first']} - {out['result']['last']} removed")
            return _done(v, out, bare)
        if cmd == "address" and sub == "add" and len(rest) == 1 and "--kind" in vals:
            out = add_address(v, "root", rest[0], vals["--kind"], site, vals.get("--name", ""), vals.get("--mac", ""),
                              vals.get("--owner", ""), vals.get("--notes", ""),
                              _on_off(vals["--dns"], "--dns") if "--dns" in vals else False,
                              vals.get("--vlan"), **common)
            print(f"{out['result']['ip']} recorded ({out['result']['kind']})")
            return _done(v, out, bare)
        if cmd == "address" and sub == "set" and len(rest) == 1:
            out = set_address(v, "root", rest[0], site, kind=_keep(vals, "--kind"),
                              name=_keep(vals, "--name", clear=True), mac=_keep(vals, "--mac", clear=True),
                              owner=_keep(vals, "--owner"), notes=_keep(vals, "--notes"),
                              dns=_keep(vals, "--dns", convert=_on_off), **common)
            print(f"{out['result']['ip']} changed")
            return _done(v, out, bare)
        if cmd == "address" and sub == "remove" and len(rest) == 1:
            out = remove_address(v, "root", rest[0], site, **common)
            print(f"{out['result']['ip']} removed")
            return _done(v, out, bare)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
