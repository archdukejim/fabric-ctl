import secrets as _random
import string

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.radius.normalize_radius_clients import normalize_radius_clients
from fabriclib.secrets.save_secrets import save_secrets


def add_radius_client(actor, name, address, message_authenticator=True, secret=None, source="cli", vendor="generic",
                      transport="udp"):
    """Purpose: Add a switch or access point that may ask FreeRADIUS (vars.yaml radius_clients) and keep its shared
             secret in fabric's secrets (radius_secrets). Applied by the next apply.
    Inputs:  actor — str, who asks (audit).
             name — str (lower-cased; a-z, 0-9, -; up to 32).
             address — str IP address or network (not 0/0, no overlap with other clients).
             message_authenticator — bool, default True.
             secret — str the device already has (16-128 printable, no spaces, quotes, backslashes or $), or None for a
             random 32-character one.
             source — "cli" (default) or "web". Reads/writes vars.yaml under vars_lock.
             vendor — "unifi", "cisco" or "generic" (default): its profile (manual 1.11.1.2).
             transport — "udp" (default) or "radsec" (only for a vendor whose profile offers it, 1.11.1.3).
    Returns: the shared secret (str), to be shown once.
    Fails:   ValidationError "802.1X is off (install_freeradius: false)" or one from normalize_radius_clients (name,
             duplicate, address, overlap, secret, vendor, transport); errors from save_secrets; OSError or
             yaml.YAMLError from vars_lock /
             load_vars / save_vars / write_audit.
    Feeds:   agent route POST /v1/radius/clients (fabric-agent, src/agent/, called by the web UI);
             run_radius_command (add-client).
    """
    secret = secret or "".join(_random.choice(string.ascii_letters + string.digits) for _ in range(32))
    with vars_lock():
        data = load_vars()
        if not data.get("install_freeradius"):
            raise ValidationError("802.1X is off (install_freeradius: false)")
        current = data.get("radius_clients") or []
        clients, _ = normalize_radius_clients(current + [{"name": name, "address": address, "secret": secret,
                                                          "message_authenticator": message_authenticator,
                                                          "vendor": vendor, "transport": transport}])
        save_secrets({"radius_secrets": {clients[-1]["name"]: secret}})
        data["radius_clients"] = clients
        save_vars(data)
    c = clients[-1]
    write_audit(actor, "RADIUS_CLIENT_ADD", f"client={c['name']} address={c['address']} "
                                            f"message_authenticator={c['message_authenticator']} vendor={c['vendor']} "
                                            f"transport={c['transport']}", source)
    return secret
