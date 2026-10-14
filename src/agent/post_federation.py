import os

from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import VARS_FILE
from fabriclib.federation.change_site_role import change_site_role
from fabriclib.federation.remake_site_group import remake_site_group
from fabriclib.federation.request_dc_type import request_dc_type
from fabriclib.federation.rodc_lost import rodc_lost


def post_federation(route, actor, data):
    """Purpose: the federation's changes from the console, each for federation:admin (central IT's, decisions 2.1.9.21,
             2.1.9.23 and 2.1.6.58 as revised 2026-10-14): POST /v1/federation/roles — a role granted at a site below
             this one, taken back, or its group made again (manual 1.9.8.20); POST /v1/federation/dc-type/<site> — a
             site below asked to change its DC type, its one-time change token answered once (manual 1.9.8.22.1);
             POST /v1/federation/rodc-lost/<site> — a site's read-only DC lost or stolen: every account it held reset,
             the DC removed.
    Inputs:  route — segments after /v1/ (already authorized: federation:admin); actor — the token's user (audit);
             data — the JSON body: for roles site, role, member ("" for the site's own admins), action
             grant|revoke|remake (remake: role "admins" or a grantable role; member unused); for dc-type to
             (writable|rodc); for rodc-lost confirm (the site's name, typed back).
    Returns: roles: change_site_role's {"site", "role", "group", "member", "granted", "changed"}, or for remake
             remake_site_group's {"site", "role", "group", "remade", "made", "changed"}; dc-type: request_dc_type's
             {"token", "site", "to", "id", "expires", "was"}; rodc-lost: rodc_lost's {"plan", "reset", "removed",
             "changed"}.
    Fails:   ValidationError (-> 400): "action: grant, revoke or remake", and the refusals of change_site_role,
             remake_site_group, request_dc_type (a site not below this one, the type it has already, replication
             unhealthy, …) and rodc_lost (the confirmation is not the site's name: "not confirmed: nothing was
             changed", audited); RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route (POST federation/...)."""
    if route == ["federation", "roles"]:
        action = read_text(data, "action")
        if action == "remake":
            return remake_site_group(load_vars(), actor, read_text(data, "site"), read_text(data, "role"))
        if action not in ("grant", "revoke"):
            raise ValidationError("action: grant, revoke or remake")
        return change_site_role(load_vars(), actor, read_text(data, "site"), read_text(data, "role"),
                                read_text(data, "member"), action == "grant")
    if len(route) == 3 and route[:2] == ["federation", "dc-type"]:
        return request_dc_type(load_vars(), actor, route[2], read_text(data, "to").strip().lower(), source="web")
    if len(route) == 3 and route[:2] == ["federation", "rodc-lost"]:
        site = route[2].strip().lower()
        typed = read_text(data, "confirm").strip().lower()
        return rodc_lost(load_vars(), os.path.dirname(VARS_FILE), actor, site,
                         confirmed=lambda plan: typed == site, source="web")
    raise RouteNotFound()
