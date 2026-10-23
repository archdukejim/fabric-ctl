def option_owner(overview, target):
    """Purpose: The subnet or reservation a DHCP options target names (manual 1.10.4.40.1), with its own options and
             netboot preset, looked up in the site's option sets before its effective options are asked for.
    Inputs:  overview — option_sets' dict; target — "", "site", "subnet:<name or network>" or "address:<ip>".
    Returns: the subnet's or reservation's dict, or None for "", "site" and another kind (the agent refuses that).
    Fails:   LookupError for a subnet or reservation that is not in the site's plan (the page answers 404,
             decision 2.1.8.16).
    Feeds:   dhcp_options; src/webui/routes/options_page."""
    kind, _, name = target.partition(":")
    if kind not in ("subnet", "address"):
        return None
    for s in overview.get("subnets") or []:
        if kind == "subnet" and name in (s["name"], s["cidr"]):
            return s
        for r in s.get("reservations") or []:
            if kind == "address" and r["ip"] == name:
                return r
    raise LookupError(f"no {'subnet' if kind == 'subnet' else 'reservation'} {name} in {overview.get('site')}'s plan")
