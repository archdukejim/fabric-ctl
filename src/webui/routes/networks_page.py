import re

from webui import agentclient as actions
from webui import views


def networks_page(h, ctx, path, query):
    """Purpose: the Networks tab (manual 1.10.4.9, 1.10.4.21): GET /networks shows a site's plan (?site=, this one by
             default), one subnet's map and address table (?subnet=<name>) or the rows matching a search (?q= an
             address, name or MAC, or part of one); GET /networks/export downloads the site's address table as CSV.
    Inputs:  h — the request handler (send, deny); ctx — page context; path — "/networks" or "/networks/export";
             query — dict: site, subnet, q, msg, err.
    Returns: 200 the page; 200 text/csv as an attachment for the export; 404 for another path.
    Fails:   agent errors propagate to handle_request (400 a site this console does not show, 403 without
             dhcp:read, 503 the agent down).
    Feeds:   get_page."""
    site = query.get("site", "")
    if path == "/networks/export":
        res = actions.networks_export(site)
        name = re.sub(r"[^A-Za-z0-9._-]", "_", str(res.get("name") or "addresses.csv"))
        return h.send(200, res["csv"], "text/csv; charset=utf-8",
                      [("Content-Disposition", f'attachment; filename="{name}"')])
    if path == "/networks":
        return h.send(200, views.networks(ctx, actions.networks_overview(site), query.get("subnet", ""),
                                          query.get("q", ""), query.get("msg", ""), query.get("err", "")))
    return h.deny(404, "Not found.")
