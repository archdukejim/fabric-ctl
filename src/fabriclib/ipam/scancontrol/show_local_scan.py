def show_local_scan(state):
    """Purpose: whether a site's own admins may scan, as `fabricctl ipam local-scan` prints it (manual 1.10.4.29.5).
    Inputs:  state — read_local_scan's result.
    Returns: str, lines ending in a newline.
    Fails:   KeyError for a value that is not read_local_scan's.
    Feeds:   run_scan_command."""
    lines = [f"local scans at {state['site']}: {'allowed' if state['allowed'] else 'off'} ({state['source']}"
             + (f": {state['set_by']}" if state["set_by"] else "") + ")"]
    if state["top"]:
        lines.append("  the top site's admins may always scan its subnets")
    else:
        lines.append("  set by the sites above it; a site above may also scan here (fabricctl ipam scan <subnet> "
                     f"--site {state['site']}, at that site)")
    if state["why"]:
        lines.append(f"  {state['why']}")
    if state.get("stale"):
        lines.append(f"  note: {state['stale']}")
    return "\n".join(lines) + "\n"
