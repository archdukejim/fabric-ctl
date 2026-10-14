from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.ipam.scancontrol.set_local_scan import set_local_scan


def post_local_scan(route, actor, data):
    """Purpose: the console's setting of whether a site below this one may scan locally (manual 1.10.4.29.5, decision
             2.1.10.30): POST /v1/ipam/local-scan (dhcp:write). The site is checked by set_local_scan (a site below
             this one, never this one) before the domain is asked; AD decides too. Nothing is applied.
    Inputs:  route — segments after /v1/ (["ipam", "local-scan"]); actor — the verified user; data — the body: site,
             allowed ("on", "off" or "clear": the value removed).
    Returns: set_local_scan's result ({"result": {"site", "allowed", "set_by"}, "warnings", "done", "site"}).
    Fails:   ValidationError (-> 400): allowed neither on, off nor clear, a field that is not text,
             what set_local_scan refuses (this site, a site not below it, the directory refusing);
             RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route.py."""
    if route[2:]:
        raise RouteNotFound()
    allowed = read_text(data, "allowed").lower()
    if allowed not in ("on", "off", "clear"):
        raise ValidationError("allowed is on, off or clear")
    return set_local_scan(load_vars(), actor, read_text(data, "site"), "clear" if allowed == "clear"
                          else allowed == "on", source="web")
