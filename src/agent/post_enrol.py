from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.load_vars import load_vars
from fabriclib.pki.scep.enrol_apple import enrol_apple
from fabriclib.pki.scep.enrol_p12 import enrol_p12
from fabriclib.pki.scep.withdraw_challenge import withdraw_challenge


def post_enrol(route, actor, data, perms):
    """Purpose: device enrolment's changes (manual 1.5.3): POST /v1/pki/enrol/apple, /v1/pki/enrol/p12 and
             /v1/pki/enrolments/<id>/withdraw, one fabriclib.pki.scep file each.
    Inputs:  route — segments after /v1/ (already authorized: pki:enrol); actor — the token's user; data — the body:
             name, device, ssid, wired (apple); name, device, legacy (p12); perms — the token's permissions (None for
             a root peer): pki:revoke (or root) may withdraw anyone's profile.
    Returns: enrol_apple's, enrol_p12's or withdraw_challenge's result.
    Fails:   ValidationError from the readers and fabriclib (-> 400); RouteNotFound for another route (-> 404).
    Feeds:   agent/post_route (POST pki/enrol/..., pki/enrolments/...)."""
    if route == ["pki", "enrol", "apple"]:
        return enrol_apple(load_vars(), actor, read_text(data, "name"), read_text(data, "device"),
                           read_text(data, "ssid"), bool(data.get("wired")))
    if route == ["pki", "enrol", "p12"]:
        return enrol_p12(load_vars(), actor, read_text(data, "name"), read_text(data, "device"),
                         bool(data.get("legacy")))
    if len(route) == 4 and route[:2] == ["pki", "enrolments"] and route[3] == "withdraw":
        return withdraw_challenge(actor, route[2], may_withdraw_any=perms is None or "pki:revoke" in perms)
    raise RouteNotFound()
