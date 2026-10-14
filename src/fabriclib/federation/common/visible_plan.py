from fabriclib.federation.network_conflicts import network_conflicts


def visible_plan(plan, names):
    """Purpose: the address plan as this console may show it (2.1.9.22, manual 1.9.8.20): only the networks of the
             sites it shows (visible_sites: this site and the sites below it; the top sees all), and their overlaps
             with each other; an overlap with a site it does not show is counted, never named, so a branch knows to
             ask the top without learning its sibling's networks.
    Inputs:  plan — read_address_plan's list (every site's networks: "site", "cidr", "name", "allow_overlap", …);
             names — the site names this console shows, or None for every site (the top, sites_shown).
    Returns: {"plan": [network], "overlaps": [network_conflicts items with "site"], "hidden_overlaps": int (overlaps
             with a site not shown, unallowed ones only)}.
    Fails:   ValueError from network_conflicts for a network that is not one.
    Feeds:   federation_overview, show_networks."""
    keep = {str(p.get("site", "")).lower() for p in plan} if names is None else {str(n).lower() for n in names}
    shown = [p for p in plan if str(p.get("site", "")).lower() in keep]
    overlaps, hidden = [], 0
    for site in sorted({p["site"] for p in shown}):
        for c in network_conflicts([p for p in shown if p["site"] == site], plan, site):
            if str(c["other_site"]).lower() in keep:
                overlaps.append({**c, "site": site})
            elif not c["allowed"]:
                hidden += 1
    return {"plan": shown, "overlaps": overlaps, "hidden_overlaps": hidden}
