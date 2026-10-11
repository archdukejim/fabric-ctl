from agent.read_strings import read_strings
from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.dns.add_record import add_record
from fabriclib.dns.add_zone import add_zone
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.create_zone_tsig_key import create_zone_tsig_key
from fabriclib.dns.remove_record import remove_record
from fabriclib.dns.remove_tsig_key import remove_tsig_key
from fabriclib.dns.remove_zone import remove_zone
from fabriclib.dns.rotate_tsig_key import rotate_tsig_key


def post_dns(route, actor, data):
    """Purpose: DNS changes: POST /v1/zones/<key>/records[/delete] and /v1/tsig[/<name>/rotate|delete].
    Inputs:  route — segments after /v1/; actor — the verified user; data — the body: type, name, ip|target|… for a
             record (index for a delete); name, zone, scope, hosts, types, secret for a TSIG key.
    Returns: the new record; {"key", "secret", "ini"} for a new key (the secret shown once); {"secret", "ini"} for a
             rotation; {} for a TSIG delete; remove_record's result for a record delete.
    Fails:   ValidationError for an unsupported record type, an invalid index or what fabriclib refuses (-> 400);
             RouteNotFound for another route.
    Feeds:   agent/post_route.py."""
    if route == ["zones"]:
        hide = data.get("hide_public") in (True, "on", "true", "1")
        return add_zone(actor, read_text(data, "name"), hide_public=hide, source="web")
    if len(route) == 3 and route[0] == "zones" and route[2] == "delete":
        return remove_zone(actor, route[1], read_text(data, "confirm"), source="web")
    if len(route) == 3 and route[0] == "zones" and route[2] == "records":
        rtype = data.get("type", "")
        if rtype not in RECORD_TYPES:
            raise ValidationError("unsupported record type")
        return add_record(actor, route[1], rtype, data, source="web")
    if len(route) == 4 and route[0] == "zones" and route[2:] == ["records", "delete"]:
        try:
            index = int(data.get("index", -1))
        except (TypeError, ValueError):
            raise ValidationError("invalid index")
        return remove_record(actor, route[1], str(data.get("type", "")), index, str(data.get("name", "")),
                             source="web")
    if route == ["tsig"]:
        key, secret, ini = create_zone_tsig_key(actor, read_text(data, "name"), read_text(data, "zone"),
                                                read_text(data, "scope"), read_strings(data, "hosts"),
                                                read_strings(data, "types"), read_text(data, "secret"), source="web")
        return {"key": key, "secret": secret, "ini": ini}
    if len(route) == 3 and route[0] == "tsig" and route[2] == "rotate":
        secret, ini = rotate_tsig_key(actor, route[1], source="web")
        return {"secret": secret, "ini": ini}
    if len(route) == 3 and route[0] == "tsig" and route[2] == "delete":
        remove_tsig_key(actor, route[1], source="web")
        return {}
    raise RouteNotFound()
