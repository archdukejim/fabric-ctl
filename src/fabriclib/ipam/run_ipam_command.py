import sys

from fabriclib.common.apply_intent import apply_intent
from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.common.apply_dhcp_change import apply_dhcp_change
from fabriclib.ipam.cli.args import parse_args
from fabriclib.ipam.cli.run_plan_change import run_plan_change
from fabriclib.ipam.cli.run_plan_read import run_plan_read
from fabriclib.ipam.offer_reservations import offer_reservations
from fabriclib.ipam.options.run_option_command import run_option_command
from fabriclib.ipam.scan_subnet import scan_subnet
from fabriclib.ipam.scancontrol.run_scan_command import run_scan_command
from fabriclib.ipam.show_scan import show_scan
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
       fabricctl ipam scan <subnet> [--no-ask] [--no-apply]   which addresses answer, and which nobody recorded:
                                                       offers to make one a reservation (this site's subnets)
       fabricctl ipam scan <subnet> --site S [--no-wait]   a scan at another site: requested, its poll runs it
       fabricctl ipam scan-requests [--site S]         a site's scan requests and their answers
       fabricctl ipam option|class|netboot ...         DHCP options, client classes, netboot (`option --help`)
       fabricctl ipam watch [--scheduled]              the plan poll once (fabric-plan-watch.timer runs it)
       fabricctl ipam sync                             Sync now: the plan poll at once, and BIND's records when DNS
                                                       waits for them (this site's own)
   --site S: another site's plan (any site your grants' networks rights reach, manual 1.6.13.12); a change to
   this site's plan applies at once unless --no-apply"""


def _sync(v, site, secrets, container):
    """Purpose: `fabricctl ipam sync`: Sync now, and what it did.
    Inputs:  v — the rendered vars; site — --site's value (refused: a sync is this site's own); secrets, container —
             as sync_plan.
    Returns: 0.
    Fails:   ValidationError from sync_plan, or for --site.
    Feeds:   run_ipam_command."""
    if site:
        raise ValidationError("a sync is this site's own: run it at that site")
    out = sync_plan(v, "root", container=container, secrets=secrets)
    print(f"plan poll: {out['state']}" + ("; Kea updated" if out["kea_restarted"] else "; Kea unchanged")
          + ("; firewall brought in line" if out["firewall"] else ""))
    if out.get("why"):
        print(out["why"])
    print("DNS: " + (("published: " + (", ".join(out["dns"]["zones"]) or "nothing changed in the zones"))
                     if out["dns"] else "already in line with the plan"))
    if out["dns"] and out["dns"].get("flushed"):
        print(f"filtering resolver: {out['dns']['flushed']} published name(s) flushed from its cache (2.1.10.46)")
    if out["dns"] and out["dns"].get("flush_error"):
        print(f"warning: {out['dns']['flush_error']}")
    return 0


def _scan(v, subnet, bare, secrets, container):
    """Purpose: `fabricctl ipam scan <subnet>`: the scan here, its result, then (on a terminal, unless --no-ask) the
             offer to record each find, applied unless --no-apply.
    Inputs:  v — the rendered vars; subnet — its name or network; bare — the bare flags; secrets, container — as
             offer_reservations.
    Returns: exit status (apply_dhcp_change's when something was recorded, else 0).
    Fails:   ValidationError from scan_subnet.
    Feeds:   run_ipam_command."""
    result = scan_subnet(v, "root", subnet)
    sys.stdout.write(show_scan(result))
    if result["unrecorded"] and "--no-ask" not in bare and sys.stdin.isatty():
        with apply_intent():          # the finds recorded, then applied: the plan poll leaves Kea to it (2.1.10.45)
            if offer_reservations(v, result, secrets=secrets, container=container):
                return apply_dhcp_change(["--no-apply"] if "--no-apply" in bare else [])
    return 0


def run_ipam_command(v, argv, secrets=None, container="samba"):
    """Purpose: `fabricctl ipam …` — the address manager's plan from the command line (manual 1.10.4.9, 1.10.4.16;
             Volume 4: 4.10.2): show, find and export, the site's number, and changes to VLANs, subnets (several
             per VLAN, 2.1.10.18), ranges and addresses, this site's or (--site) any site the caller's networks
             rights reach (1.6.13.12); `option`, `class`, `netboot` and `watch` (the plan poll) go to
             run_option_command; `sync` is Sync now (sync_plan, 1.10.4.28); `scan` of this site's subnet
             (scan_subnet, 1.10.4.22), and a scan at another site and the requests' answers through run_scan_command
             (1.10.4.36). Routes only: every rule is in the function each command calls; the reads and changes of
             the plan are cli/run_plan_read and cli/run_plan_change.
    Inputs:  v — the rendered vars (SetupContext.load_state().vars); argv — list of str after "ipam" (default
             show); secrets — fabric's secrets (default: loaded by the functions); container — the DC's container
             (tests name their own). Run as root, acting for the Enterprise Admin. See USAGE.
    Returns: exit status: 0 success (and help); 1 a refusal (ValidationError, printed with why) or a failed apply;
             2 usage (printed to stderr).
    Fails:   ValidationError is caught (exit 1); other exceptions propagate.
    Feeds:   fabriclib/cli.py (`fabricctl ipam`)."""
    if argv[:1] in (["--help"], ["-h"], ["help"]):
        print(USAGE)
        return 0
    cmd, args = (argv[0], argv[1:]) if argv else ("show", [])
    if cmd == "watch":                                    # the plan poll itself: never under the apply intent
        return run_option_command(v, cmd, args, secrets, container)
    if cmd in ("option", "class", "netboot"):             # the options and netboot: their own flags
        with apply_intent():                              # the poll leaves the change to its apply (2.1.10.45)
            return run_option_command(v, cmd, args, secrets, container)
    if cmd == "scan-requests" or (cmd == "scan" and "--site" in args):   # a scan at another site (1.10.4.36)
        return run_scan_command(v, cmd, args, secrets, container)
    try:
        pos, vals, bare = parse_args(args)
        site = vals.get("--site", "")
        if cmd == "sync" and not pos:                                      # Sync now (1.10.4.28)
            return _sync(v, site, secrets, container)
        if cmd == "scan" and len(pos) == 1 and not site:                   # this site's subnet (1.10.4.22)
            return _scan(v, pos[0], bare, secrets, container)
        code = run_plan_read(v, cmd, pos, site, secrets, container)
        if code is None:
            with apply_intent():      # a change and its apply: the plan poll leaves Kea to the apply (2.1.10.45)
                code = run_plan_change(v, cmd, pos, vals, bare, site, secrets, container)
        if code is not None:
            return code
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
