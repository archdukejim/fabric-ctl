import os

from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import VARS_FILE
from fabriclib.federation.rodc_lost import rodc_lost


def post_federation(route, actor, data):
    """Purpose: the federation's changes from the console: POST /v1/federation/rodc-lost/<site> (system:admin) — a
             site's read-only DC is lost or stolen (decision 2.1.6.58): every account it held reset, the DC removed.
    Inputs:  route — segments after /v1/ (already authorized); actor — the token's user (audit); data — the body:
             confirm (the site's name, typed back).
    Returns: rodc_lost's result ({"plan", "reset", "removed", "changed"}).
    Fails:   ValidationError (-> 400) from rodc_lost: the confirmation is not the site's name ("not confirmed:
             nothing was changed", audited), and its other refusals; RouteNotFound for another route (-> 404).
    Feeds:   agent/post_route (POST federation/...)."""
    if len(route) == 3 and route[:2] == ["federation", "rodc-lost"]:
        site = route[2].strip().lower()
        typed = read_text(data, "confirm").strip().lower()
        return rodc_lost(load_vars(), os.path.dirname(VARS_FILE), actor, site,
                         confirmed=lambda plan: typed == site, source="web")
    raise RouteNotFound()
