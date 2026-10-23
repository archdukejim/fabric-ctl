import urllib.parse

from webui.devpreview.fabric_rules import ValidationError, required_permission
from webui.devpreview.fake_account import managed
from webui.devpreview.sample_data import SAMPLE_ACCESS, SAMPLE_DOMAIN, SAMPLE_GPO

try:                                       # the agent's own store and its words, from a checkout (as fabric_rules)
    from agent.pending_store import PendingStore
    from agent.pending_thing import PAGES, describe_change, pending_page_of
except ImportError:
    PendingStore = None


def _find(rows, key, value):
    """Purpose: The sample row whose key is a value.
    Inputs:  rows — list of dicts; key, value — str.
    Returns: the row or None.
    Fails:   never.
    Feeds:   _thing."""
    return next((r for r in rows or [] if str(r.get(key)) == str(value)), None)


def _thing(state, route, body):
    """Purpose: The preview's read of what a change changes, as the agent's thing_state reads it (2.1.8.14).
    Inputs:  state — DevState; route — segments after /v1/; body — dict.
    Returns: the sample row or value (None for a new one).
    Fails:   never.
    Feeds:   fake_pending (the store's state)."""
    head, name = route[0], (route[1] if len(route) > 1 else body.get("uid") or body.get("name", ""))
    if route[:2] == ["account", "groups"]:            # a member change from My account: its managed group
        group = _find(managed(state), "name", route[2] if len(route) > 2 else "")
        if group is None:
            raise ValidationError(f"no group {route[2] if len(route) > 2 else ''}")
        return group
    if head == "people":
        return _find(state.data["people"]["users"], "uid", name)
    if head == "machines":
        return _find(SAMPLE_DOMAIN["machines"], "name", name)
    if head == "host-groups":
        return _find(SAMPLE_ACCESS["groups"], "short", name) or _find(SAMPLE_ACCESS["groups"], "name", name)
    if head == "sudo":
        return _find(SAMPLE_ACCESS["sudo"], "name", name)
    if route == ["domain", "password-policy"]:
        return SAMPLE_DOMAIN["policy"]
    if head == "gpo":
        return {"settings": SAMPLE_GPO.get("settings"), "controls": SAMPLE_GPO.get("controls")}
    raise ValidationError("this change is not held in the preview")


def _store(state, who, run):
    """Purpose: The preview's pending store: the agent's own PendingStore over the sample data, its jobs done at once.
    Inputs:  state — DevState (keeps the store); who — the preview's person; run — (route, body) -> answer: the fake
             agent's change.
    Returns: the PendingStore.
    Fails:   never.
    Feeds:   fake_pending."""
    if getattr(state, "pending", None) is None:
        def start_job(kind, owner, fn):
            jobs = state.data.setdefault("jobs", {})
            job_id = f"dev-{len(jobs) + 1}"
            jobs[job_id] = {"id": job_id, "kind": kind, "state": "done", "error": "", "result": fn()}
            return {"id": job_id}

        state.pending = PendingStore(run=lambda route, actor, body, perms, session: run(route, body),
                                     state=lambda route, body: _thing(state, route, body),
                                     need=lambda route: required_permission("POST", route), start_job=start_job,
                                     finish=lambda page: ("Write the policy into the domain (restarts only what "
                                                          "changed)", lambda actor: None) if page == "domain" else None)
    return state.pending


def fake_pending(state, who, method, route, body, run):
    """Purpose: The fake agent's Apply per page (manual 1.8.6.5): GET /v1/pending and /v1/pending/<page>, POST
             /v1/pending/hold and /v1/pending/<page>/drop|discard|apply, with the agent's own store and checks.
    Inputs:  state — DevState; who — {"user", "perms"}; method — "GET" or "POST"; route — segments after /v1/; body —
             dict; run — (route, body) -> answer: the fake agent's change (raising ValidationError for a refusal).
    Returns: the answer, or None for another route (or without the agent's code: the preview then holds nothing).
    Fails:   ValidationError as the agent refuses.
    Feeds:   fake_agent."""
    if route[:1] != ["pending"] or PendingStore is None:
        return None
    store, user, perms = _store(state, who, run), who["user"], set(who["perms"])

    def may_see(page):
        return PAGES.get(page) == "session" or PAGES.get(page) in perms

    if method == "GET":
        if route == ["pending"]:
            return store.counts(user, may_see)
        return store.page(user, route[1], may_see) if len(route) == 2 and route[1] in PAGES else None
    if route == ["pending", "hold"]:
        parts = [urllib.parse.unquote(p) for p in str(body.get("route", "")).split("/") if p]
        page = pending_page_of(parts)
        if page is None:
            raise ValidationError("this change is not held: it is done at once")
        change = body.get("body") or {}
        return store.hold(user, perms, page, parts, change, describe_change(parts, change))
    if len(route) == 3 and route[1] in PAGES and route[2] in ("drop", "discard", "apply"):
        if route[2] == "drop":
            return store.drop(user, route[1], str(body.get("id", "")) or "-")
        if route[2] == "discard":
            return store.drop(user, route[1])
        return store.apply(user, perms, route[1], user, None)
    return None
