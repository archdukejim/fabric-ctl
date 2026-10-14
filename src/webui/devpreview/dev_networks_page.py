from webui import views
from webui.devpreview.fabric_rules import export_plan, networks_view
from webui.devpreview.sample_networks import (SAMPLE_NETWORK_LEASES, SAMPLE_NETWORK_READ, SAMPLE_NETWORK_SITES,
                                              SAMPLE_NETWORK_VARS, SAMPLE_LOCAL_SCAN, SAMPLE_LOCAL_SCAN_BELOW,
                                              SAMPLE_SCAN_REQUESTS, SAMPLE_SYNC)


def dev_networks_page(h, path, query):
    """Purpose: the Networks tab in the dev preview: the real page over the sample plan (sample_networks), drawn by
             fabriclib's own networks_view when the preview runs from a checkout; /networks/export as the real CSV.
             A site the sample does not show is refused as production refuses it (400).
    Inputs:  h — the dev handler (send, ctx); path — "/networks" or "/networks/export"; query — dict (site, subnet, q,
             msg, err).
    Returns: None; sends the page, the CSV, or an error page.
    Fails:   never for the sample data.
    Feeds:   dev_get_page."""
    site = query.get("site") or "lan"
    if site not in [s["name"] for s in SAMPLE_NETWORK_SITES]:
        return h.send(400, views.error_page(400, f"site {site!r} is not this site or one below it: this console "
                                                 "shows lan, parents"))
    if networks_view is None:
        overview = {"site": site, "own": "lan", "sites": [], "vlans": [], "networks": [], "leases_shown": False,
                    "stale": "", "leases_error": "", "block": None, "suggested_block": None,
                    "error": "dev preview from the image has no fabriclib; run it from a checkout"}
        return h.send(200, views.networks(h.ctx, overview))
    leases = SAMPLE_NETWORK_LEASES if site == "lan" else None
    if path == "/networks/export":
        return h.send(200, export_plan(SAMPLE_NETWORK_READ, site, leases, "lan"), "text/csv; charset=utf-8")
    overview = networks_view(SAMPLE_NETWORK_VARS, SAMPLE_NETWORK_READ, site, SAMPLE_NETWORK_SITES, leases)
    overview.update(own="lan", stale="", error="", leases_error="",
                    local_scan=SAMPLE_LOCAL_SCAN if site == "lan" else SAMPLE_LOCAL_SCAN_BELOW,
                    scan_requests=[] if site == "lan" else SAMPLE_SCAN_REQUESTS, scan_requests_error="",
                    sync=SAMPLE_SYNC if site == "lan" else None)
    return h.send(200, views.networks(h.ctx, overview, query.get("subnet", ""), query.get("q", ""),
                                      query.get("msg", ""), query.get("err", "")))
