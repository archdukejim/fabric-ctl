import re

from webui import agentclient as actions
from webui import views


def networks_page(h, ctx, path, query):
    """Purpose: DHCP · Networks (manual 1.10.4.40.1): GET /networks shows a site's plan (?site=, this one by default)
             as a list, a VLAN's page (?vlan=<id>), a subnet's (?subnet=<name>), an address's (&address=<ip>), Add
             VLAN or the site's number on their own page (?view=new-vlan|number), or a search (?q=); GET
             /networks/export downloads the site's address table as CSV.
    Inputs:  h — the request handler (send, deny); ctx — page context; path — "/networks" or "/networks/export";
             query — dict: site, view, vlan, subnet, address, q.
    Returns: 200 the page; 200 text/csv as an attachment; 404 for a site, VLAN, subnet or address that is not there
             (decision 2.1.8.16).
    Fails:   agent errors propagate to handle_request (400 the DC not answering for another site, 403 without
             dhcp:read, 503 the agent down).
    Feeds:   get_page."""
    site = query.get("site", "")
    try:
        if path == "/networks/export":
            res = actions.networks_export(site or actions.networks_overview()["site"])
            name = re.sub(r"[^A-Za-z0-9._-]", "_", str(res.get("name") or "addresses.csv"))
            return h.send(200, res["csv"], "text/csv; charset=utf-8",
                          [("Content-Disposition", f'attachment; filename="{name}"')])
        overview = actions.networks_overview(site)
    except actions.NotFound as exc:
        return h.deny(404, f"Not found: {exc}.")
    try:
        return h.send(200, views.networks(ctx, overview, query))
    except LookupError as exc:
        return h.deny(404, f"Not found: {exc.args[0]}.")
