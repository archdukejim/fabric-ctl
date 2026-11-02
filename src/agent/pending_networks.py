# The address manager's pages whose changes are held (manual 1.10.4.40.2): the routes of each, and the grant's right
# each change needs at its site (1.10.4.34), checked when it is held and again at Apply
OPTION_KINDS = ("options", "classes", "option-defs", "netboot")
RIGHTS = {"networks": "networks:plan", "options": "networks:options"}


def networks_page_of(route):
    """Purpose: The address manager's page a change is held on: Networks for a change to a site's plan (and a scan's
             find recorded), DHCP options for an option, class, definition or netboot preset.
    Inputs:  route — the change's segments after /v1/.
    Returns: "networks", "options", or None (not one of the address manager's held changes).
    Fails:   never.
    Feeds:   agent/pending_thing.pending_page_of, post_pending."""
    if route[:1] == ["networks"] and len(route) >= 3 and route[1]:
        return "networks"
    if route == ["ipam", "scan", "record"]:
        return "networks"
    if len(route) == 2 and route[0] == "ipam" and route[1] in OPTION_KINDS:
        return "options"
    return None


def _this_site():
    """Purpose: This install's site, for a change that names none (a scan's find, an option of this site).
    Inputs:  none (reads vars.yaml).
    Returns: str ("" when the settings cannot be read).
    Fails:   never.
    Feeds:   networks_site."""
    from fabriclib.common.load_vars import load_vars
    try:
        return str(load_vars().get("site_name") or "")
    except (OSError, ValueError):
        return ""


def networks_site(route, body):
    """Purpose: The site a held change of the address manager changes: the route's for Networks, the body's (or this
             site's) for an option, "domain" for the domain's own set (scope domain, or a class of it: domain
             true).
    Inputs:  route — segments after /v1/; body — the change's body.
    Returns: str.
    Fails:   never.
    Feeds:   describe_networks, networks_state, networks_key, networks_grant."""
    if route[0] == "networks":
        return route[1]
    if route[:2] == ["ipam", "scan"]:
        return _this_site()
    if str(body.get("scope") or "") == "domain" or body.get("domain") is True:     # the set, or one of its classes
        return "domain"
    return str(body.get("site") or "") or _this_site()


def _at(site):
    """Purpose: where a change is, as people read it.
    Inputs:  site — networks_site's answer.
    Returns: str (" at <site>", or " in the domain's set").
    Fails:   never.
    Feeds:   describe_networks."""
    return " in the domain's set" if site == "domain" else f" at {site}"


def _describe_option(kind, body, where):
    """Purpose: an options page change in a sentence.
    Inputs:  kind — one of OPTION_KINDS; body — its body; where — _at's text.
    Returns: str.
    Fails:   never.
    Feeds:   describe_networks."""
    off = str(body.get("action") or "") in ("remove", "off", "undefine")
    target = str(body.get("target") or "")
    if kind == "options":
        on = f" on {body.get('scope')} {target}".rstrip() if body.get("scope") not in ("site", "domain") else ""
        verb = "Remove" if off else "Set"
        return f"{verb} option {body.get('option', '')}{on}{where}"
    if kind == "classes":
        return f"{'Remove' if off else 'Add'} client class {body.get('name', '')}{where}"
    if kind == "option-defs":
        return f"{'Undefine' if off else 'Define'} option {body.get('name', '')}{where}"
    return f"Switch network boot {'off' if off else 'on'} for {target}{where}"


def describe_networks(route, body):
    """Purpose: A held change of the address manager in a sentence ("Add VLAN 30 (cams) at lan").
    Inputs:  route — segments after /v1/; body — its body.
    Returns: str.
    Fails:   never.
    Feeds:   agent/pending_thing.describe_change."""
    where = _at(networks_site(route, body))
    if route[0] == "ipam" and route[1] == "scan":
        return f"Record {body.get('ip', '')} (found by a scan) as a {body.get('kind') or 'reservation'}{where}"
    if route[0] == "ipam":
        return _describe_option(route[1], body, where)
    sub, b = route[2:], body
    gone = sub[-1:] == ["delete"]
    if sub == ["block"]:
        return f"Set the site's number to {b.get('number', '')}{where}"
    if sub[0] == "vlans":
        if len(sub) == 1:
            at = f"@{b['location']}" if b.get("location") else ""      # another location of the site (1.10.4.46)
            return f"Add VLAN {b.get('id', '')}{at} ({b.get('name', '')}){where}"
        return f"{'Remove' if gone else 'Change'} VLAN {sub[1]}{where}"
    if sub[0] == "subnets":
        if len(sub) == 1:
            return f"Add subnet {b.get('cidr', '')} to VLAN {b.get('vlan', '')}{where}"
        return f"{'Remove' if gone else 'Change'} subnet {sub[1]}{where}"
    if sub[0] == "ranges":
        if gone:
            return f"Remove the range from {b.get('first', '')} in VLAN {b.get('vlan', '')}{where}"
        return f"Add {b.get('kind', '')} range {b.get('first', '')} - {b.get('last', '')}{where}"
    if len(sub) == 1:
        return f"Record {b.get('ip', '')} as {b.get('kind', '')}{where}"
    return f"{'Remove' if gone else 'Change'} {sub[1]}{where}"


def networks_state(route, body, v):
    """Purpose: The thing a held change of the address manager changes, as read now (decision 2.1.8.14): the site's
             plan with its option sets as the DC has it (but when it was read), or the domain's set; nested under
             one key, so no field of a change's body is taken for one of the plan's on the Review.
    Inputs:  route — segments after /v1/; body — its body; v — vars.
    Returns: {"plan": site_plan's dict without "read"}, or {"domain_options": the domain's set}.
    Fails:   ValidationError: the DC cannot be read now, or "no such site: <s>".
    Feeds:   agent/pending_thing.thing_state."""
    from fabriclib.ipam.common.site_plan import site_plan
    from fabriclib.ipam.read_plan import read_plan
    site = networks_site(route, body)
    of = v.get("site_name", "") if site == "domain" else site
    plan = site_plan(read_plan(v, of=of), of)
    if site == "domain":
        return {"domain_options": plan.get("domain_options")}
    return {"plan": {k: x for k, x in plan.items() if k != "read"}}


def networks_key(route, body):
    """Purpose: Which thing a held change of the address manager changes, as a key: every change to one site's plan
             (and its options) shares it, the domain's set has its own.
    Inputs:  route — segments after /v1/; body — its body.
    Returns: ("plan", site).
    Fails:   never.
    Feeds:   agent/pending_thing.thing_key."""
    return "plan", networks_site(route, body)


def networks_grant(v, caller, route, body):
    """Purpose: The grant's networks right a held change needs at its site (manual 1.10.4.34; 1.10.4.40.2), checked
             by fabric-agent when it is held and again at Apply, before the thing is read: `plan` for Networks,
             `options` for the DHCP options page (at every site for the domain's set).
    Inputs:  v — vars; caller — the signed-in person; route — segments after /v1/; body — its body.
    Returns: None (the change is not the address manager's, or the grant gives the right).
    Fails:   ValidationError saying why it is refused ("no grant gives you networks plan at lab"), or that the domain
             controller is not running.
    Feeds:   agent/post_pending (the store's check)."""
    page = networks_page_of(route)
    if page is None:
        return None
    from fabriclib.access.check_access import check_access
    site = networks_site(route, body)
    check_access(v, caller, RIGHTS[page], {"site": "all" if site == "domain" else site})
    return None

