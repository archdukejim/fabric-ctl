from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.federation.change_site_role import change_site_role


def post_federation(route, actor, data):
    """Purpose: answer POST /v1/federation/roles (manual 1.9.8.20, 2.1.9.21): a role granted at a site below this one,
             or taken back.
    Inputs:  route — segments after /v1/ (already authorized: federation:admin); actor — the audit's user; data — the
             JSON body: site, role, member ("" for the site's own admins), action grant|revoke.
    Returns: change_site_role's {"site", "role", "group", "member", "granted", "changed"}.
    Fails:   ValidationError (-> 400) "action: grant or revoke" and change_site_role's refusals (this site itself, a
             site not below it); RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route."""
    if route != ["federation", "roles"]:
        raise RouteNotFound()
    action = read_text(data, "action")
    if action not in ("grant", "revoke"):
        raise ValidationError("action: grant or revoke")
    return change_site_role(load_vars(), actor, read_text(data, "site"), read_text(data, "role"),
                            read_text(data, "member"), action == "grant")
