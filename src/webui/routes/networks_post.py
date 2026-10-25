import urllib.parse

from webui import agentclient as actions
from webui.routes.held import held, q
from webui.routes.networks_scan_post import networks_scan_post
from webui.routes.options_post import options_post

# the plan's changes, as the segments after the site (1.10.4.21.5); "*" is a VLAN ID, a subnet's name or an address
CHANGES = (["block"], ["vlans"], ["vlans", "*"], ["vlans", "*", "delete"], ["subnets"], ["subnets", "*"],
           ["subnets", "*", "delete"], ["ranges"], ["ranges", "delete"], ["addresses"], ["addresses", "*"],
           ["addresses", "*", "delete"])
FIELDS = ("number", "id", "name", "subnet", "no_subnet", "gateway", "purpose", "notes", "access", "dhcp", "relay",
          "allow_overlap", "split", "force", "vlan", "cidr", "kind", "first", "last", "ip", "mac", "owner", "dns",
          "location", "to_location")


def _back(site, rest, form):
    """Purpose: The page a plan change goes back to: the subnet's or VLAN's page the form was on, the site's list
             after a VLAN's or subnet's removal.
    Inputs:  site — str; rest — the segments after the site; form — dict (back_vlan, back_subnet).
    Returns: str, "/networks?site=…[&vlan=…|&subnet=…]".
    Fails:   never.
    Feeds:   networks_post."""
    keep = {"site": site}
    gone = rest[-1:] == ["delete"] and rest[0] in ("vlans", "subnets")
    if form.get("back_subnet") and not gone:
        keep["subnet"] = form["back_subnet"]
    elif form.get("back_vlan") and not gone:
        keep["vlan"] = form["back_vlan"]
    return "/networks?" + urllib.parse.urlencode(keep)


def _sync(h):
    """Purpose: Sync now, done at once (manual 1.10.4.40.2): the plan poll at once and DNS published; back to
             Networks with what it did, or why it was refused.
    Inputs:  h — the request handler (back).
    Returns: 303 to /networks with the outcome.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   networks_post."""
    try:
        res = actions.sync_now()
    except actions.ValidationError as exc:
        return h.back("/networks", err=f"Sync now: {exc}")
    dns = res.get("dns")
    return h.back("/networks", msg=(
        "Synced: " + ("Kea updated" if res.get("kea_restarted") else "Kea already in line")
        + ("; firewall brought in line" if res.get("firewall") else "")
        + ("; DNS published (" + (", ".join(dns.get("zones") or []) or "no zone changed") + ")" if dns
           else "; DNS already in line") + "." + (" " + res["why"] if res.get("why") else "")
        + (" Warning: " + dns["flush_error"] + "." if dns and dns.get("flush_error") else "")))


def networks_post(h, sess, parts, form):
    """Purpose: Route a signed-in, CSRF-checked POST under /networks/ (manual 1.10.4.40.1): plan/<site>/<change>
             holds a change to the site's plan for Networks' Apply; sync is Sync now, at once; scan[/…] the scan
             page's (networks_scan_post); options/<kind> the DHCP options page's (options_post).
    Inputs:  h — the request handler (back, deny); sess — the session (the scan's result page); parts —
             URL-decoded segments after /networks/; form — dict (csrf, back_vlan or back_subnet: the page to go
             back to, and the change's fields of FIELDS).
    Returns: 303 back to the page with "Waiting for Apply: …" or the refusal; 404 for another path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/networks/…)."""
    if parts == ["sync"]:
        return _sync(h)
    if parts[:1] == ["scan"]:
        return networks_scan_post(h, sess, parts[1:], form)
    if parts[:1] == ["options"]:
        return options_post(h, parts[1:], form)
    if len(parts) < 3 or parts[0] != "plan" or not parts[1]:
        return h.deny(404, "Not found.")
    site, rest = parts[1], parts[2:]
    if not any(len(c) == len(rest) and all(p in ("*", r) for p, r in zip(c, rest)) for c in CHANGES):
        return h.deny(404, "Not found.")
    body = {k: form[k] for k in FIELDS if isinstance(form.get(k), str)}
    return held(h, _back(site, rest, form), "networks/" + "/".join(q(x) for x in [site, *rest]), body)
