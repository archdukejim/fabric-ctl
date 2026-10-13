from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.ipam.common.site_scope import site_scope
from fabriclib.ipam.scanpolicy.set_scan_policy import set_scan_policy


def post_scan_policy(route, actor, data):
    """Purpose: the console's changes to the scan policy (manual 1.10.4.27.5, decision 2.1.10.28): POST
             /v1/ipam/scan-policy sets a site's level (dhcp:write; a site this console shows), POST
             /v1/ipam/scan-policy/org the organisation's (dhcp:org-options, checked by the permission table; AD then
             decides whether this site may write it). Nothing is applied: the next scan reads it.
    Inputs:  route — segments after /v1/ (["ipam", "scan-policy"] or [..., "org"]); actor — the verified user; data —
             the body: site, policy (allow, deny or inherit) for a site; policy (allow or deny), enforced (on, off or
             left out) for the organisation.
    Returns: set_scan_policy's result ({"result": {"level", "site", "policy", "enforced"}, "warnings", "done",
             "site"}).
    Fails:   ValidationError (-> 400): a site this console does not show, an on/off field that is neither, a field
             that is not text, what set_scan_policy refuses; RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route.py."""
    v = load_vars()
    if route[2:] == ["org"]:
        enforced = read_text(data, "enforced").lower()
        if enforced not in ("", "on", "off"):
            raise ValidationError("enforced is on or off")
        return set_scan_policy(v, actor, "org", read_text(data, "policy"), None if not enforced else enforced == "on",
                               source="web")
    if route[2:]:
        raise RouteNotFound()
    site = site_scope(v, read_text(data, "site"))
    return set_scan_policy(v, actor, "site", read_text(data, "policy"), None, site, source="web")
