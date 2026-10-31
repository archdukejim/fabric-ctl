from agent.read_strings import read_strings
from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.directory.set_person_group import set_person_group
from fabriclib.domain.create_group import create_group
from fabriclib.domain.remove_group import remove_group
from fabriclib.domain.set_group_managers import set_group_managers


def post_groups(route, actor, data, caller):
    """Purpose: a group's changes (manual 1.6.12.5, 1.6.12.12; 2.1.6.67's two levels): POST /v1/groups (create:
             `groups:admin`), /v1/groups/<name>/delete and /managers (level 1: `groups:admin`),
             /v1/groups/<name>/members
             (level 2: any signed-in person, fabric-agent's check deciding: the tier above the group or its managers
             within their controls). Each acts at once, one fabriclib function over its body alone.
    Inputs:  route — ["groups"] or ["groups", <name>, "delete"|"managers"|"members"]; actor — str; data — the body
             (create: name, description; managers: managers (a list), add, remove (booleans), only_from; members:
             action add|remove, member); caller — the token's user, or None for a root peer.
    Returns: create: {"name", "gid"}; delete: {"name"}; managers: {"name", "managers", "add", "remove", "only_from",
             "changed"}; members: {"uid", "group", "member", "changed"}.
    Fails:   ValidationError (-> 400): "add and remove must be true or false", "action: add or remove", "unknown
             operation", or fabriclib's refusal with why.
    Feeds:   agent/post_route.py (POST groups/...)."""
    v = load_vars()
    if route == ["groups"]:
        return create_group(v, actor, read_text(data, "name"), read_text(data, "description"), caller=caller)
    if len(route) != 3:
        raise ValidationError("unknown operation")
    name, action = route[1], route[2]
    if action == "delete":
        return remove_group(v, actor, name, caller=caller)
    if action == "managers":
        if not all(isinstance(data.get(k, False), bool) for k in ("add", "remove")):
            raise ValidationError("add and remove must be true or false")
        return set_group_managers(v, actor, name, read_strings(data, "managers"), data.get("add", False),
                                  data.get("remove", False), read_text(data, "only_from"), caller=caller)
    if action == "members":
        if data.get("action") not in ("add", "remove"):
            raise ValidationError("action: add or remove")
        return set_person_group(v, actor, name, read_text(data, "member"), data["action"] == "add", caller=caller)
    raise ValidationError("unknown operation")
