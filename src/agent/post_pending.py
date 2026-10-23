import urllib.parse

from agent.job_store import JOBS
from agent.pending_store import PendingStore
from agent.pending_thing import PAGES, describe_change, pending_page_of, thing_state
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.rbac.required_permission import required_permission


def _run(route, actor, body, perms, session):
    """Purpose: Do one held change at Apply: the same route a direct call takes (agent/post_route), unchanged.
    Inputs:  route, actor, body, perms, session — as post_route takes them.
    Returns: the route's result.
    Fails:   as the route (ValidationError with fabriclib's refusal).
    Feeds:   PENDING (its run)."""
    from agent.post_route import post_route        # imported here: post_route routes /v1/pending/... to this module
    return post_route(route, actor, body, perms, session)


def _finish(page, routes=()):
    """Purpose: What a page's changes still need once all are done: a password policy changed on Policies is fabric's
             setting, written into the domain's services, restarting only what changed, health-gated (manual
             1.8.6.5, 1.6.12.10, 2.1.14.15).
    Inputs:  page — a page id; routes — the routes of the changes being applied.
    Returns: (what, fn(actor)) for "policies" when the password policy is among them, and for "kerberos" when the
             ticket policy is (written into the DC's KDC, 1.6.12.9); None otherwise (Group Policy and sudo rules are
             written by their own changes).
    Fails:   never (fn raises ValidationError when the apply does not finish).
    Feeds:   PENDING (its finish)."""
    wanted = {"policies": ["domain", "password-policy"], "kerberos": ["domain", "kerberos", "policy"]}.get(page)
    if wanted is None or wanted not in [list(r) for r in routes]:
        return None

    def write(actor):
        from fabriclib.system.apply_changes import apply_changes
        ok, output = apply_changes(actor, source="web")
        if not ok:
            tail = (output or "").strip().splitlines()[-1:]
            raise ValidationError("the apply did not finish" + (f": {tail[0]}" if tail else ""))

    return "Write the policy into the domain (restarts only what changed)", write


PENDING = PendingStore(run=_run, state=lambda route, body: thing_state(route, body, load_vars()),
                       need=lambda route: required_permission("POST", route),
                       start_job=JOBS.start, finish=_finish)


def _wrapped(data):
    """Purpose: The change a hold names: its route (as after /v1/, e.g. "people/sam/disable") and its body.
    Inputs:  data — the hold's JSON body: {"route": str (its segments URL-quoted), "body": dict}.
    Returns: (route segments, body).
    Fails:   ValidationError for a missing or malformed route or body.
    Feeds:   post_pending."""
    route, body = data.get("route"), data.get("body", {})
    if not isinstance(route, str) or not route or not isinstance(body, dict):
        raise ValidationError("hold: a route and a body object")
    parts = [urllib.parse.unquote(p) for p in route.strip("/").split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise ValidationError("hold: a route and a body object")
    return parts, body


def post_pending(route, actor, data, perms, session):
    """Purpose: Apply per page (manual 1.8.6.5): POST /v1/pending/hold (a change held on its page), and for a page
             /v1/pending/<page>/drop (body: id), /discard (all of the person's on the page) and /apply (as one job).
             Every one is the signed-in person's own: a root peer (the host) acts at once and holds nothing.
    Inputs:  route — ["pending", ...]; actor — the audit's name; data — the JSON body; perms — the token's permissions
             (None for a root peer); session — the token's sid.
    Returns: hold: {"id", "page", "what", "pending"}; drop and discard: {"dropped", "pending"}; apply: {"id"} (the
             job), the page's queue showing it to everyone who may see the page.
    Fails:   ValidationError (-> 400): a root peer, a change that is not held (done at once), the change's permission
             missing, an unknown page, nothing pending; RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route (POST /v1/pending/...)."""
    if perms is None:
        raise ValidationError("a pending change belongs to a signed-in person")
    if route == ["pending", "hold"]:
        parts, body = _wrapped(data)
        page = pending_page_of(parts)
        if page is None:
            raise ValidationError("this change is not held: it is done at once")
        return PENDING.hold(actor, perms, page, parts, body, describe_change(parts, body))
    if len(route) != 3 or route[1] not in PAGES:
        raise RouteNotFound()
    page, op = route[1], route[2]
    if op == "drop":
        if not str(data.get("id", "")):
            raise ValidationError("drop: the change's id")
        return PENDING.drop(actor, page, str(data["id"]))
    if op == "discard":
        out = PENDING.drop(actor, page)
        write_audit(actor, "PENDING_DISCARD", f"{page}: {out['dropped']} change(s)", source="web")
        return out
    if op == "apply":
        job = PENDING.apply(actor, perms, page, actor, session)
        write_audit(actor, "PENDING_APPLY", f"{page}: started", source="web")
        return job
    raise RouteNotFound()
