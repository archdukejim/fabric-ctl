from webui import agentclient as actions
from webui import views


def networks_scan_page(h, ctx, query):
    """Purpose: The scan page, a page of Networks (GET /networks/scan, manual 1.10.4.40.1): whether the person may
             scan here, and this site's subnets to pick one and scan it.
    Inputs:  h — the request handler (send); ctx — page context; query — dict (subnet: the subnet to preselect, as
             a subnet's page links it).
    Returns: 200 page.
    Fails:   agent errors propagate to handle_request (403 without dhcp:read, 503 the agent down).
    Feeds:   get_page."""
    return h.send(200, views.ipam_scan(ctx, actions.scannable_subnets(), pick=query.get("subnet", "")))
