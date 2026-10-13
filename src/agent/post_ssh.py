from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.load_vars import load_vars
from fabriclib.vault.ssh.set_ssh_certificates import set_ssh_certificates
from fabriclib.vault.ssh.sign_ssh_key import sign_ssh_key


def post_ssh(route, actor, data):
    """Purpose: SSH certificates (manual 1.6.11.9): POST /v1/ssh/sign (any sign-in; a fabric admin's certificate),
             /v1/ssh/on and /v1/ssh/off (system:admin), one fabriclib.vault.ssh file each.
    Inputs:  route — segments after /v1/ (already authorized); actor — the token's user (the certificate's principal);
             data — the body: public_key (sign).
    Returns: sign_ssh_key's or set_ssh_certificates' result.
    Fails:   ValidationError from the readers and fabriclib (-> 400); RouteNotFound for another route (-> 404).
    Feeds:   agent/post_route (POST ssh/...)."""
    if route == ["ssh", "sign"]:
        return sign_ssh_key(load_vars(), actor, read_text(data, "public_key"))
    if route in (["ssh", "on"], ["ssh", "off"]):
        return set_ssh_certificates(actor, route[1] == "on")
    raise RouteNotFound()
