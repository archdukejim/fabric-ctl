from agent.route_not_found import RouteNotFound
from fabriclib.common.load_vars import load_vars
from fabriclib.ipam.sync.sync_plan import sync_plan


def post_ipam_sync(route, actor, data, caller=None):
    """Purpose: the console's Sync now (manual 1.10.4.28, decision 2.1.10.29): POST /v1/ipam/sync runs the plan poll at
             once and, when DNS waits, publishes BIND's records by the quick path; never an apply. The signed-in
             person needs the grants' networks `plan` right at this site (sync_plan checks it first, 1.10.4.35).
    Inputs:  route — segments after /v1/ (["ipam", "sync"]); actor — the verified user; data — the body ({}; nothing
             is read from it); caller — the signed-in person (None: a root peer).
    Returns: sync_plan's result ({"state", "kea_restarted", "firewall", "dns_pending", "dns"}).
    Fails:   ValidationError (-> 400): what sync_plan refuses (the grant, an apply running, DHCP off, not upgraded) or
             what failed (said with what was done); RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route.py."""
    if route != ["ipam", "sync"]:
        raise RouteNotFound()
    return sync_plan(load_vars(), actor, source="web", caller=caller)
