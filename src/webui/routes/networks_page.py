import re
import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.routes.one_site import ONE_SITE, other_site


def networks_page(h, ctx, path, query):
    """Purpose: Networks · Segments (manual 1.10.4.40.1): GET /networks shows this site's plan (?site= may name only
             this site: 1.8.6.14) as a list, a VLAN's page (?vlan=<id>), a subnet's (?subnet=<name>), an address's
             (&address=<ip>), Add VLAN or the site's number on their own page (?view=new-vlan|number), or a search
             (?q=); GET /networks/rules is Networks · Access, the site's access table (2.1.10.61; the old
             ?view=rules redirects there); GET /networks/export downloads the site's address table as CSV.
    Inputs:  h — the request handler (send, deny, redirect); ctx — page context; path — "/networks",
             "/networks/rules" or "/networks/export";
             query — dict: site, view, vlan, subnet, address, q.
    Returns: 200 the page; 303 from ?view=rules to /networks/rules; 200 text/csv as an attachment; 404 for a VLAN,
             subnet or address that is not there (decision 2.1.8.16), and for another site (ONE_SITE, 2.1.8.68).
    Fails:   agent errors propagate to handle_request (403 without dhcp:read, 503 the agent down).
    Feeds:   get_page."""
    site = query.get("site", "")
    if path == "/networks" and query.get("view") == "rules":       # the old address of the rules (2.1.10.61)
        return h.redirect("/networks/rules" + ("?" + urllib.parse.urlencode({"site": site}) if site else ""))
    try:
        overview = actions.networks_overview()            # this site's: the console shows no other (1.8.6.14)
        if other_site(site, overview.get("site")):
            return h.deny(404, ONE_SITE + ".")
        if path == "/networks/export":
            res = actions.networks_export(overview["site"])
            name = re.sub(r"[^A-Za-z0-9._-]", "_", str(res.get("name") or "addresses.csv"))
            return h.send(200, res["csv"], "text/csv; charset=utf-8",
                          [("Content-Disposition", f'attachment; filename="{name}"')])
    except actions.NotFound as exc:
        return h.deny(404, f"Not found: {exc}.")
    try:
        if path == "/networks/rules":
            return h.send(200, views.networks(ctx, overview, {"site": site, "view": "rules",
                                                              "net": query.get("net", "")}))
        return h.send(200, views.networks(ctx, overview, {**query, "view": "" if query.get("view") == "rules"
                                                          else query.get("view", "")}))
    except LookupError as exc:
        return h.deny(404, f"Not found: {exc.args[0]}.")
