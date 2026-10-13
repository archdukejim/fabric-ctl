from webui import agentclient as actions
from webui import views


def networks_scan_page(h, ctx, query):
    """Purpose: render the scan page (GET /networks/scan, manual 1.10.4.22, 1.10.4.27): the scan policy in force here,
             and the subnets of this site's plan, to pick one and scan it.
    Inputs:  h — the request handler (send); ctx — page context; query — dict (msg, err: the last change's outcome;
             subnet: the subnet to preselect, from the Networks tab's subnet view).
    Returns: 200 page.
    Fails:   agent errors propagate to handle_request (403 without dhcp:read, 503 agent down).
    Feeds:   get_page."""
    scan = actions.scannable_subnets()
    return h.send(200, views.ipam_scan(ctx, scan["subnets"], None, query.get("msg", ""), query.get("err", ""),
                                       query.get("subnet", ""), scan.get("policy"), scan.get("policy_error", "")))
