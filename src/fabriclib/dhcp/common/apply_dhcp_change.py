from fabriclib.security.refresh_firewall import refresh_firewall
from fabriclib.system.apply_changes import apply_changes


def apply_dhcp_change(args):
    """Purpose: Apply a just-recorded DHCP or address-plan change now, unless --no-apply was given, then bring the host
             firewall in line with it (refresh_firewall: the change is the admin's yes to the rules it implies, manual
             1.10.3.5).
    Inputs:  args — list of str (looks for "--no-apply"). Runs apply_changes as root (interactive.py --apply).
    Returns: 0 if skipped or applied; 1 if apply or the firewall failed (last 2000 characters of its output).
    Fails:   subprocess.TimeoutExpired (900 s, 300 s) and OSError from apply_changes / refresh_firewall propagate.
    Feeds:   dhcp/run_dhcp_command (every change), ipam/cli/report_change (a change to this site's plan),
             ipam/run_ipam_command (a scan's finds recorded)."""
    if "--no-apply" in args:
        print("recorded; apply with: sudo fabricctl --apply")
        return 0
    ok, output = apply_changes("root", "cli")
    print("applied (Kea reloaded)" if ok else output[-2000:])
    if not ok:
        return 1
    ok, output = refresh_firewall()
    print("host firewall: in line" if ok else output[-2000:])
    return 0 if ok else 1
