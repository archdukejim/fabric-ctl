from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.localadmin.ack_local_admin_ssh import ack_local_admin_ssh
from fabriclib.localadmin.checkout_local_admin import checkout_local_admin
from fabriclib.localadmin.set_local_admin_ssh import set_local_admin_ssh


def post_local_admin(route, actor, data, caller, config_dir=None):
    """Purpose: the fabric host's local-admin through the console (manual 1.7.1.4.5, 1.7.1.4.6; decisions 2.1.7.18,
             2.1.7.19, 2.1.7.21): POST /v1/local-admin/checkout (body: reason) and POST /v1/local-admin/ssh (body: ssh
             on|off, or ack to acknowledge its alert; dc optional). The route needs only a sign-in; the Enterprise
             Admin's tier is checked by the functions (the DC decides the caller's tier): fabric-admin signed in, or a
             root peer.
    Inputs:  route — ["local-admin", "checkout"|"ssh"]; actor — the audit's user; data — the body; caller — the
             token's user (None: a root peer); config_dir — the install's config folder (default the vars file's).
    Returns: checkout: {"password", "version", "rotates_after", "reason"}; ssh: {"dc", "ssh", "changed", "applied"};
             ssh ack: {"dc", "ack", "changed"}.
    Fails:   ValidationError (-> 400): "unknown operation", or the functions' refusals (below the Enterprise Admin, no
             reason, OpenBao locked, a read-only DC, …).
    Feeds:   agent/post_route.py (POST local-admin/...)."""
    v = load_vars()
    config = config_dir or f"{v['deploy_base_dir']}/fabric/config"
    if route == ["local-admin", "checkout"]:
        return checkout_local_admin(v, config, caller, actor, read_text(data, "reason"), source="web")
    if route == ["local-admin", "ssh"] and read_text(data, "ssh") == "ack":
        return ack_local_admin_ssh(v, config, caller, actor, read_text(data, "dc") or None, source="web")
    if route == ["local-admin", "ssh"]:
        return set_local_admin_ssh(v, config, caller, actor, read_text(data, "ssh"), read_text(data, "dc") or None,
                                   source="web")
    raise ValidationError("unknown operation")
