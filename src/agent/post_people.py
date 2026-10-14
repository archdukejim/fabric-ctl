from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.directory.create_person import create_person
from fabriclib.directory.remove_person import remove_person
from fabriclib.directory.reset_sign_in import reset_sign_in
from fabriclib.directory.set_person_enabled import set_person_enabled
from fabriclib.directory.set_person_group import set_person_group
from fabriclib.directory.unlock_person import unlock_person
from fabriclib.rbac.holds_permission import holds_permission


def post_people(route, actor, data, perms):
    """Purpose: answer POST /v1/people[/<uid>/<action>] (manual 1.6.3.8, 1.6.3.16, 1.6.3.18): route each change to its
             fabriclib function. A caller who holds a route's permission only in its site helpdesk form (2.1.9.21)
             acts on this site's own people who hold no role only (own_site).
    Inputs:  route — segments after /v1/ (already authorized, starting with "people"); actor — the audit's user; data —
             the JSON body; perms — the token's permissions (None for a root peer: everything).
    Returns: people: {"password"} (one-time, shown once); <uid>/reset: {"password"}; <uid>/unlock: {"uid",
             "unlocked"}; <uid>/disable|enable: {"uid", "enabled", "changed"}; <uid>/delete (body: confirm):
             {"uid", "revoked"}; <uid>/groups (body: action add|remove, group): {"uid", "group", "member",
             "changed"}. A fabric-group member's changes only with system:admin (or root).
    Fails:   ValidationError (-> 400) for what fabriclib refuses (another site's person for the site helpdesk);
             RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route."""
    v = load_vars()
    privileged = perms is None or "system:admin" in perms     # root, or the admin bundle

    def own(need):            # the permission held only as the site helpdesk: this site's own people
        return perms is not None and holds_permission(perms, need) == "site"
    if route == ["people"]:
        return {"password": create_person(v, actor, read_text(data, "uid"), read_text(data, "first"),
                                          read_text(data, "last"), read_text(data, "email"))}
    if len(route) != 3:
        raise RouteNotFound()
    uid, action = route[1], route[2]
    if action == "reset":
        return {"password": reset_sign_in(v, actor, uid, privileged, own_site=own("people:reset"))}
    if action == "unlock":
        return unlock_person(v, actor, uid, privileged, own_site=own("people:unlock"))
    if action in ("disable", "enable"):
        return set_person_enabled(v, actor, uid, action == "enable", privileged, own_site=own("people:disable"))
    if action == "delete":
        return remove_person(v, actor, uid, read_text(data, "confirm"), privileged)
    if action == "groups":
        if data.get("action") not in ("add", "remove"):
            raise ValidationError("action: add or remove")
        return set_person_group(v, actor, read_text(data, "group"), uid, data["action"] == "add", privileged)
    raise RouteNotFound()
