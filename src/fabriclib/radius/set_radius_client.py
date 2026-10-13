from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.radius.normalize_radius_clients import normalize_radius_clients


def set_radius_client(actor, name, vendor=None, transport=None, source="cli"):
    """Purpose: Change a RADIUS client's vendor (its profile, manual 1.11.1.2) or its transport (RADIUS/UDP or RadSec,
             1.11.1.3); its address, secret and Message-Authenticator setting stay. Applied by the next apply.
    Inputs:  actor — str, who asks (audit).
             name — str (lower-cased).
             vendor — "unifi", "cisco", "generic", or None to keep it.
             transport — "udp", "radsec", or None to keep it.
             source — "cli" (default) or "web". Reads/writes vars.yaml under vars_lock.
    Returns: the client's entry after the change ({"name", "address", "message_authenticator", "vendor",
             "transport"}).
    Fails:   ValidationError "802.1X is off (install_freeradius: false)", "no RADIUS client …", "nothing to change:
             give a vendor or a transport", or one from normalize_radius_clients (unknown vendor, transport, RadSec for
             a vendor without it); nothing is saved then. OSError or yaml.YAMLError from the vars helpers and
             write_audit.
    Feeds:   agent route POST /v1/radius/clients/<name>/set (fabric-agent, called by the web UI);
             run_radius_command (set-client).
    """
    name = str(name).strip().lower()
    if vendor is None and transport is None:
        raise ValidationError("nothing to change: give a vendor or a transport")
    with vars_lock():
        data = load_vars()
        if not data.get("install_freeradius"):
            raise ValidationError("802.1X is off (install_freeradius: false)")
        current = [dict(c) for c in data.get("radius_clients") or []]
        target = next((c for c in current if c.get("name") == name), None)
        if target is None:
            raise ValidationError(f"no RADIUS client {name}")
        if vendor is not None:
            target["vendor"] = vendor
        if transport is not None:
            target["transport"] = transport
        clients, _ = normalize_radius_clients(current)
        data["radius_clients"] = clients
        save_vars(data)
    entry = next(c for c in clients if c["name"] == name)
    write_audit(actor, "RADIUS_CLIENT_SET", f"client={name} vendor={entry['vendor']} transport={entry['transport']}",
                source)
    return entry
