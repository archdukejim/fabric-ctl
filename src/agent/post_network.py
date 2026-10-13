from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.load_vars import load_vars
from fabriclib.radius.add_radius_client import add_radius_client
from fabriclib.radius.coa.coa_session import coa_session
from fabriclib.radius.map_radius_group import map_radius_group
from fabriclib.radius.remove_radius_client import remove_radius_client
from fabriclib.radius.rotate_radius_secret import rotate_radius_secret
from fabriclib.radius.set_radius_client import set_radius_client
from fabriclib.radius.unmap_radius_group import unmap_radius_group
from fabriclib.system.apply_changes import apply_changes


def post_network(route, actor, data):
    """Purpose: 802.1X settings, each saved and applied at once: POST /v1/radius/clients[/<name>/rotate|delete|set],
             /v1/radius/people[/<group>/delete] (DHCP: post_dhcp); and the sessions' Disconnect and CoA, sent at
             once and not applied: POST /v1/radius/sessions/disconnect | reauthenticate (manual 1.11.1.4).
    Inputs:  route — segments after /v1/; actor — the verified user; data — the body (name, address,
             message_authenticator, secret, vendor, transport; group, vlan, priority; client, session, bounce).
    Returns: the saved mapping, the client's secret (shown once) or its entry (set), with "applied" (bool) and the
             last 2000 characters of the apply's output; for a session: coa_session's result.
    Fails:   ValidationError from the readers and fabriclib (-> 400); RouteNotFound for another route.
    Feeds:   agent/post_route.py."""
    if len(route) == 3 and route[:2] == ["radius", "sessions"] and route[2] in ("disconnect", "reauthenticate"):
        action = "disconnect" if route[2] == "disconnect" else "bounce" if data.get("bounce") else "reauthenticate"
        return coa_session(load_vars(), actor, action, read_text(data, "client"), read_text(data, "session"),
                           source="web")
    if route == ["radius", "clients"]:
        result = {"secret": add_radius_client(actor, read_text(data, "name"), read_text(data, "address"),
                                              bool(data.get("message_authenticator", True)),
                                              read_text(data, "secret") or None, source="web",
                                              vendor=read_text(data, "vendor") or "generic",
                                              transport=read_text(data, "transport") or "udp")}
    elif len(route) == 4 and route[:2] == ["radius", "clients"] and route[3] == "set":
        result = {"client": set_radius_client(actor, route[2], read_text(data, "vendor") or None,
                                              read_text(data, "transport") or None, source="web")}
    elif route == ["radius", "people"]:
        result = {"mapping": map_radius_group(actor, read_text(data, "group"), read_text(data, "vlan") or None,
                                              read_text(data, "priority") or 100, source="web")}
    elif len(route) == 4 and route[:2] == ["radius", "people"] and route[3] == "delete":
        unmap_radius_group(actor, route[2], source="web")
        result = {}
    elif len(route) == 4 and route[:2] == ["radius", "clients"] and route[3] in ("rotate", "delete"):
        secret = None
        if route[3] == "rotate":
            secret = rotate_radius_secret(actor, route[2], read_text(data, "secret") or None, source="web")
        else:
            remove_radius_client(actor, route[2], source="web")
        result = {"secret": secret}
    else:
        raise RouteNotFound()
    ok, output = apply_changes(actor, source="web")
    return {**result, "applied": ok, "output": output[-2000:]}
