import contextlib
import urllib.parse

from agent.job_store import JOBS
from agent.pending_networks import networks_grant, networks_page_of
from agent.pending_store import PendingStore
from agent.pending_thing import PAGES, describe_change, pending_page_of, thing_state
from agent.route_not_found import RouteNotFound
from fabriclib.common.apply_intent import apply_intent
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.rbac.required_permission import required_permission


def _run(route, actor, body, perms, session):
    """Purpose: Do one held change at Apply: the same route a direct call takes (agent/post_route), unchanged; the
             address manager's without their own apply, which the page's finish does once (1.10.4.40.3).
    Inputs:  route, actor, body, perms, session — as post_route takes them.
    Returns: the route's result.
    Fails:   as the route (ValidationError with fabriclib's refusal).
    Feeds:   PENDING (its run)."""
    page = networks_page_of(route)
    if page:                                        # the signed-in person is the caller the grant is checked for
        from agent.post_ipam_scan import post_ipam_scan
        from agent.post_networks import post_networks
        from agent.post_options import post_options
        call = post_networks if route[0] == "networks" else post_ipam_scan if route[1] == "scan" else post_options
        return call(route, actor, body, actor, apply=False)
    from agent.post_route import post_route        # imported here: post_route routes /v1/pending/... to this module
    return post_route(route, actor, body, perms, session)


def _finish(page, routes=()):
    """Purpose: What a page's changes still need once all are done: a password policy changed on Policies is fabric's
             setting, written into the domain's services, restarting only what changed, health-gated (manual
             1.8.6.5, 1.6.12.10, 2.1.14.15).
    Inputs:  page — a page id; routes — the routes of the changes being applied.
    Returns: (what, fn(actor)) for "policies" when the password policy is among them, for "kerberos" when the
             ticket policy is (written into the DC's KDC, 1.6.12.9), and for "zones" when a record, a landing-page link
             or a TSIG key's removal is (_finish_dns), for "networks" and "options" when this site's plan or
             its options may have changed (_finish_plan); None otherwise (Group Policy and sudo rules are written
             by their own changes, a zone's add and removal publish themselves).
    Fails:   never (fn raises ValidationError when the apply does not finish).
    Feeds:   PENDING (its finish)."""
    if page == "zones":                       # DNS: BIND alone, and the landing page (2.1.8.24)
        return _finish_dns(routes)
    if page in ("networks", "options"):        # the address manager: this site's plan applied once
        return _finish_plan(page, routes)
    wanted = {"policies": ["domain", "password-policy"], "kerberos": ["domain", "kerberos", "policy"]}.get(page)
    if wanted is None or wanted not in [list(r) for r in routes]:
        return None

    def write(actor):
        from fabriclib.system.apply_changes import apply_changes
        from fabriclib.system.apply_failure import apply_failure
        ok, output = apply_changes(actor, source="web")
        if not ok:                            # its last 10 lines, and where the full output is (2.1.8.31)
            raise ValidationError(apply_failure(output))

    return "Write the policy into the domain (restarts only what changed)", write


def _finish_dns(routes):
    """Purpose: What DNS' changes need once all are done: the BIND-only deploy (dns/apply_dns, decision 2.1.8.24) when
             any of them is a record, a landing-page link or a TSIG key's removal; a zone's add and removal publish
             themselves (dns/publish_zone_list).
    Inputs:  routes — the routes being applied.
    Returns: (what, fn(actor)), or None; fn returns what its row of the Review says once done: "", that the
             landing page's certificate waits for a full apply (decision 2.1.8.29), and/or that the filtering
             resolver did not forget the changed names (a warning, 2.1.4.9).
    Fails:   never (fn raises ValidationError when BIND does not take the change).
    Feeds:   _finish."""
    if all(list(r) == ["zones"] or list(r)[2:] == ["delete"] and len(r) == 3 and r[0] == "zones" for r in routes):
        return None

    def publish(actor):
        from fabriclib.dns.apply_dns import apply_dns
        from agent.landing_note import landing_note
        done = apply_dns(actor, source="web")
        notes = [landing_note(done.get("landing_cert")),
                 f"warning: {done['flush_error']}" if done.get("flush_error") else ""]   # 2.1.4.9
        return "; ".join(n for n in notes if n)

    return "Publish to BIND and the landing page (reloads only BIND)", publish


def _finish_plan(page, routes):
    """Purpose: What the address manager's changes need once all are done (manual 1.10.4.40.3): this site's plan
             applied once, Kea and the firewall brought in line (restarting only what changed, health-gated), as
             each change from the CLI does on its own; another site's plan is taken by that site's poll within
             30 s, and a site's number shapes suggestions only.
    Inputs:  page — "networks" or "options"; routes — the routes being applied.
    Returns: (what, fn(actor)), or None when no change is this site's (Networks: every change names its site;
             an options change always applies here, since the domain's set and its classes are this site's too).
    Fails:   never (fn raises ValidationError when the apply or the firewall does not finish).
    Feeds:   _finish."""
    site = load_vars().get("site_name", "")
    if page == "networks" and not any(list(r) == ["ipam", "scan", "record"]
                                       or (r[1] == site and list(r)[2:] != ["block"]) for r in routes):
        return None

    def apply_here(actor):
        from fabriclib.security.refresh_firewall import refresh_firewall
        from fabriclib.system.apply_changes import apply_changes
        from fabriclib.system.apply_failure import apply_failure
        ok, output = apply_changes(actor, source="web")
        if ok:
            ok, output = refresh_firewall()
        if not ok:                            # its last 10 lines, and where the full output is (2.1.8.31)
            raise ValidationError(apply_failure(output))

    return "Apply this site's plan to Kea and the firewall (restarts only what changed)", apply_here


PENDING = PendingStore(run=_run, state=lambda route, body: thing_state(route, body, load_vars()),
                       need=lambda route: required_permission("POST", route),
                       start_job=JOBS.start, finish=_finish,
                       check=lambda owner, route, body: networks_grant(load_vars(), owner, route, body),
                       # the address manager's Apply: written, then applied; the plan poll leaves Kea to it (2.1.10.45)
                       around=lambda page: apply_intent() if page in ("networks", "options")
                       else contextlib.nullcontext())


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
