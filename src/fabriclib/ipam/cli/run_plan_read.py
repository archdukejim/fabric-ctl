import sys

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.export_plan import export_plan
from fabriclib.ipam.find_in_plan import find_in_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.show_plan import show_plan
from fabriclib.ipam.suggestions import suggest_block


def _leases(v, site):
    """Purpose: this site's live leases for show, find and export; none for another site or with DHCP off.
    Inputs:  v — fabric vars (install_kea, site_name); site — the site shown ("" this one).
    Returns: list_leases' rows, or None (DHCP off, another site, Kea not answering).
    Fails:   never: a Kea error leaves the leases out.
    Feeds:   run_plan_read."""
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
    Feeds:   run_plan_read (find)."""
    for r in rows:
        print(f"{r['site']:<10} VLAN {str(r['vlan']):<5} {r['subnet']:<18} {r['ip']:<15} {r['kind']:<14} "
              f"{r['name']:<16} {r['mac']}" + (f"  ({r['range']} range)" if r["range"] else ""))


def run_plan_read(v, cmd, pos, site, secrets=None, container="samba"):
    """Purpose: `fabricctl ipam show|find|export` and `block` without a number (manual 1.10.4.16, 1.10.4.35): what the
             plan holds, any site of the domain, read as this site's agent account. Routes only.
    Inputs:  v — the rendered vars; cmd — the command; pos — its positionals; site — --site's value ("" none);
             secrets, container — as read_plan.
    Returns: exit status (0 shown; 1 find found nothing), or None when cmd and its arguments are not a read (the
             caller tries the changes, then prints the usage).
    Fails:   ValidationError from read_plan (the DC not answering, "no such site").
    Feeds:   ipam/run_ipam_command."""
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
    return None
