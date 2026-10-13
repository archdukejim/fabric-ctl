def show_scan_policy(p):
    """Purpose: the scan policy as `fabricctl ipam scan-policy` prints it (manual 1.10.4.27.5): whether scans may run,
             which level decides, both levels, and why a scan is denied.
    Inputs:  p — read_scan_policy's result.
    Returns: str, lines ending in a newline.
    Fails:   KeyError for a value that is not read_scan_policy's.
    Feeds:   run_scan_policy_command."""
    org = p["org"]
    lines = [f"scan policy at {p['site']}: {'allowed' if p['allowed'] else 'denied'} ({p['source']})",
             f"  organisation: {org['policy'] or 'unset (allow)'}" + (", enforced" if org["enforced"] else ""),
             f"  site {p['site']}: {p['site_level']['policy'] or 'inherit'}"]
    if p["why"]:
        lines.append(f"  {p['why']}")
    if p.get("stale"):
        lines.append(f"  note: {p['stale']}")
    return "\n".join(lines) + "\n"
