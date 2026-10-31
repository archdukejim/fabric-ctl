from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.directory.create_person import create_person
from fabriclib.directory.remove_person import remove_person
from fabriclib.directory.reset_sign_in import reset_sign_in
from fabriclib.directory.set_person_enabled import set_person_enabled
from fabriclib.directory.set_person_group import set_person_group
from fabriclib.domain.edit_person import edit_person
from fabriclib.domain.person_fields import FIELDS
from fabriclib.domain.unlock_person import unlock_person


def _optional(data, field):
    """Purpose: a text field that may be left out (None), as distinct from one given empty.
    Inputs:  data — the request body; field — str.
    Returns: str or None.
    Fails:   ValidationError("<field> must be text").
    Feeds:   post_people (edit)."""
    if field not in data:
        return None
    return read_text(data, field)


def post_people(route, actor, data, caller):
    """Purpose: a person's changes (manual 1.6.12.4, 1.6.12.12): POST /v1/people (add), /v1/people/<uid>/reset,
             /disable, /enable, /delete, /groups, /edit and /unlock; each one fabriclib function that runs
             fabric-agent's check first (the tiers, the grants' people rights, a group's managers: check_access) with
             the signed-in person as the caller, so a body here never decides who may do it. Each acts at once and
             takes only its body, so a page's pending store can hold and replay it unchanged.
    Inputs:  route — ["people"] or ["people", <uid>, <action>]; actor — the audit's name; data — the JSON body (add:
             uid, first, last, email; delete: confirm; groups: action add|remove, group; edit: any of
             person_fields.FIELDS, 2.1.6.93);
             caller — the token's user, or None for a root peer.
    Returns: add, reset: {"password"} (one-time, shown once); disable/enable: {"uid", "enabled", "changed"}; delete:
             {"uid", "revoked"}; groups: {"uid", "group", "member", "changed"}; edit: {"uid", "name", "email",
             "changed", "person"}; unlock: {"uid", "changed"}.
    Fails:   ValidationError (-> 400): "action: add or remove", "unknown operation", "unknown field" (edit), or
                 fabriclib's refusal with why.
    Feeds:   agent/post_route.py (POST people/...)."""
    v = load_vars()
    if route == ["people"]:
        return {"password": create_person(v, actor, read_text(data, "uid"), read_text(data, "first"),
                                          read_text(data, "last"), read_text(data, "email"), caller=caller)}
    if len(route) != 3:
        raise ValidationError("unknown operation")
    uid, action = route[1], route[2]
    if action == "reset":
        return {"password": reset_sign_in(v, actor, uid, caller=caller)}
    if action in ("disable", "enable"):
        return set_person_enabled(v, actor, uid, action == "enable", caller=caller)
    if action == "delete":
        return remove_person(v, actor, uid, read_text(data, "confirm"), caller=caller)
    if action == "groups":
        if data.get("action") not in ("add", "remove"):
            raise ValidationError("action: add or remove")
        return set_person_group(v, actor, read_text(data, "group"), uid, data["action"] == "add", caller=caller)
    if action == "edit":
        unknown = sorted(set(data) - set(FIELDS))
        if unknown:
            raise ValidationError(f"unknown field: {', '.join(unknown)} (a person's fields: {', '.join(FIELDS)})")
        return edit_person(v, actor, uid, {f: _optional(data, f) for f in FIELDS if f in data}, caller=caller)
    if action == "unlock":
        return unlock_person(v, actor, uid, caller=caller)
    raise ValidationError("unknown operation")
