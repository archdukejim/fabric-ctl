import contextlib
import secrets
import threading
import time

from agent.pending_thing import OWN_QUEUE, state_change, thing_key, version_of
from fabriclib.common.errors import ValidationError

QUEUE_KEEP = 10                  # applies kept per page for its queue, newest first
QUEUE_SECONDS = 1800             # a finished apply leaves the queue after 30 minutes
MAX_HELD = 200                   # changes one person may hold at once
SECRET_KEYS = ("password",)      # results shown once to who applied them, never in the queue (1.8.4)


class PendingStore:
    """Purpose: Apply per page (manual 1.8.6.5, decisions 2.1.8.9, 2.1.8.13, 2.1.8.14): each person's changes held per
             page until that page's Apply, each with the version of what it changes; an Apply runs them in order as
             one job, stopping at the first that fails or whose thing changed since; the page's queue (every apply,
             change by change) for everyone who may see the page. In memory: a restart of fabric-agent drops them.
    Feeds:   agent/post_pending, agent/get_route (GET /v1/pending), the dev preview's fake agent."""

    def __init__(self, run, state, need, start_job, finish=None, check=None, around=None):
        """Purpose: A store whose changes run through the given functions (the agent's own, or the preview's fakes).
        Inputs:  run — (route, actor, body, perms, session) -> result: the change done; state — (route, body) -> the
                 thing it changes as read now; need — (route) -> the permission the change needs, or None; start_job
                 — (kind, owner, fn) -> {"id"}: fn run as a job; finish — (page, routes of the changes applied) ->
                 (what, fn(actor)) or None: what a page's changes still need once all are done (a password policy
                 changed on Policies: fabric's settings written into the services, restarting only what changed,
                 2.1.14.15); check — (owner, route, body) -> None, raising ValidationError: a check of the
                 change's own beside its permission, at hold and again at Apply (the address manager's grant at
                 the change's site, 1.10.4.40.2); None: none; around — (page) -> a context manager the page's apply
                 job runs inside (the address manager's: the apply intent, so the plan poll leaves Kea to the apply,
                 2.1.10.45); None: none.
        Returns: None.
        Fails:   never.
        Feeds:   PENDING (agent/post_pending), the dev preview."""
        self.run, self.state, self.need, self.start_job = run, state, need, start_job
        self.finish = finish or (lambda page, routes: None)
        self.check = check or (lambda owner, route, body: None)
        self.around = around or (lambda page: contextlib.nullcontext())
        self.lock = threading.Lock()
        self.changes = []                # held changes, oldest first: {id, owner, page, route, body, what, ...}
        self.queue = {}                  # page -> [apply]: {id, owner, started, state, items: [{id, what, state, why}]}
        self.shown_once = {}             # owner -> [{"what", "secret"}]: results to show once, then forgotten

    def hold(self, owner, perms, page, route, body, what):
        """Purpose: Hold a change on its page: checked for its permission now (and again at Apply), with the thing it
                 changes read now: its old values and version.
        Inputs:  owner — the signed-in person; perms — their permissions; page — pending_thing.pending_page_of's id;
                 route — the change's segments after /v1/; body — its JSON body; what — the change in a sentence.
        Returns: {"id", "page", "what", "pending": how many this person holds on the page}.
        Fails:   ValidationError: no person (a root peer), without the change's permission, refused by the
                 store's check (why), too many held, or the thing cannot be read now.
        Feeds:   agent/post_pending (POST /v1/pending/hold)."""
        need = self.need(route)
        if not owner or perms is None:
            raise ValidationError("a pending change belongs to a signed-in person")
        if need is None or (need != "session" and need not in perms):
            raise ValidationError(f"you need the permission {need}" if need else "not allowed")
        self.check(owner, route, body)
        now = _read(self.state, route, body)
        change = {"id": secrets.token_urlsafe(9), "owner": owner, "page": page, "route": list(route),
                  "body": dict(body), "what": what, "old": _old(now, route, body), "new": _new(now, route, body),
                  "version": version_of(now), "made": time.time(), "changed_since": False}
        with self.lock:
            if sum(c["owner"] == owner for c in self.changes) >= MAX_HELD:
                raise ValidationError(f"at most {MAX_HELD} changes may wait: apply or discard some first")
            self.changes.append(change)
            count = sum(c["owner"] == owner and c["page"] == page for c in self.changes)
        return {"id": change["id"], "page": page, "what": what, "pending": count}

    def counts(self, owner, may_see):
        """Purpose: The top bar's and the navigation's numbers: this person's pending changes per page, and which
                 pages have an apply running that they may see.
        Inputs:  owner — the signed-in person; may_see — (page) -> bool: whether they may see the page.
        Returns: {page: {"pending": n, "running": bool}} for each page with either.
        Fails:   never.
        Feeds:   agent/get_route (GET /v1/pending)."""
        out = {}
        with self.lock:
            for c in self.changes:
                if c["owner"] == owner:
                    out.setdefault(c["page"], {"pending": 0, "running": False})["pending"] += 1
            for page, applies in self.queue.items():
                if may_see(page) and any(a["state"] == "running" and (page not in OWN_QUEUE or a["owner"] == owner)
                                         for a in applies):
                    out.setdefault(page, {"pending": 0, "running": False})["running"] = True
        return out

    def page(self, owner, page, may_see):
        """Purpose: A page's Review: this person's changes on it, the page's queue (everyone's applies, change by
                 change, with no result), and the results this person has still to see once (then forgotten).
        Inputs:  owner — the signed-in person; page — a page id; may_see — (page) -> bool.
        Returns: {"page", "changes": [{id, what, old, new, made, changed_since}], "queue": [apply], "shown_once":
                 [{what, secret}]}; the queue is empty when they may not see the page, and only their own
                 applies on a page of OWN_QUEUE (My account).
        Fails:   never.
        Feeds:   agent/get_route (GET /v1/pending/<page>)."""
        with self.lock:
            self._expire()
            mine = [{k: c[k] for k in ("id", "what", "old", "new", "made", "changed_since")} for c in self.changes
                    if c["owner"] == owner and c["page"] == page]
            queue = [{**a, "items": [dict(i) for i in a["items"]]} for a in self.queue.get(page, [])
                     if page not in OWN_QUEUE or a["owner"] == owner] if may_see(page) else []
            once = self.shown_once.pop(owner, [])
        return {"page": page, "changes": mine, "queue": queue, "shown_once": once}

    def drop(self, owner, page, change_id=None):
        """Purpose: Drop one held change, or every one of the page (Discard).
        Inputs:  owner — the signed-in person; page — a page id; change_id — one change's id, or None for all.
        Returns: {"dropped": n, "pending": how many are left on the page}.
        Fails:   ValidationError "no such change" when change_id names none of theirs on the page.
        Feeds:   agent/post_pending (drop, discard)."""
        with self.lock:
            keep = [c for c in self.changes if not (c["owner"] == owner and c["page"] == page
                                                    and change_id in (None, c["id"]))]
            dropped = len(self.changes) - len(keep)
            if change_id and not dropped:
                raise ValidationError("no such change")
            self.changes = keep
            left = sum(c["owner"] == owner and c["page"] == page for c in keep)
        return {"dropped": dropped, "pending": left}

    def apply(self, owner, perms, page, actor, session):
        """Purpose: Apply a page's changes as one job: in order, each checked again for its permission and for its
                 thing (a different version: someone changed it since, so it is held again against the thing as it
                 is now and the job stops); the first that fails stops the job; the rest stay pending.
        Inputs:  owner — the signed-in person; perms — their permissions now; page — a page id; actor — the audit's
                 name; session — their token's sid (for the routes that use it).
        Returns: {"id"}: the job (JobStore), and the page's queue shows it to everyone who may see the page.
        Fails:   ValidationError: nothing pending on the page, or an apply of theirs on the page still running.
        Feeds:   agent/post_pending (POST /v1/pending/<page>/apply)."""
        with self.lock:
            mine = [c for c in self.changes if c["owner"] == owner and c["page"] == page]
            if not mine:
                raise ValidationError("nothing is pending on this page")
            if any(a["owner"] == owner and a["state"] == "running" for a in self.queue.get(page, [])):
                raise ValidationError("your apply of this page is still running")
            entry = {"id": secrets.token_urlsafe(9), "owner": owner, "started": time.time(), "state": "running",
                     "items": [{"id": c["id"], "what": c["what"], "state": "queued", "why": ""} for c in mine]}
            last = self.finish(page, [c["route"] for c in mine])
            if last:
                entry["items"].append({"id": "finish", "what": last[0], "state": "queued", "why": ""})
            applies = self.queue.setdefault(page, [])
            applies.insert(0, entry)
            del applies[QUEUE_KEEP:]
        def job():
            with self.around(page):
                return self._run_all(owner, perms, mine, entry, actor, session, last)
        return self.start_job("apply", owner, job)

    def _run_all(self, owner, perms, mine, entry, actor, session, last=None):
        """Purpose: The apply job itself (see apply).
        Inputs:  as apply; mine — the changes, in order; entry — the page's queue entry for this apply; last — the
                 page's finish (what, fn), run when every change is done. A thing an earlier change of the same
                 apply changed is not checked again (its version moved because of this apply, not someone else).
        Returns: {"page", "items": [{what, state, why}], "applied": n}: the job's result (no secret: those are shown
                 once on the page's Review).
        Fails:   never for a change's refusal (its item's state); an unexpected error marks the apply failed
                 and propagates (the job's error).
        Feeds:   apply (as a job)."""
        applied, touched = 0, set()     # things an earlier change of this apply changed: their versions moved
        try:
            for change, item in zip(mine, entry["items"]):
                self._mark(item, "running")
                need = self.need(change["route"])
                if need is None or (need != "session" and need not in perms):
                    self._stop(entry, item, f"refused: you need the permission {need}")
                    break
                try:
                    self.check(owner, change["route"], change["body"])
                except ValidationError as exc:
                    self._stop(entry, item, f"refused: {exc}")
                    break
                try:
                    now = _read(self.state, change["route"], change["body"])
                except ValidationError as exc:
                    self._stop(entry, item, f"not run: {exc}")
                    break
                key = thing_key(change["route"], change["body"])
                if key not in touched and version_of(now) != change["version"]:
                    with self.lock:          # held again against the thing as it is now (as 1.8.5.5's plan)
                        change.update(old=_old(now, change["route"], change["body"]), version=version_of(now),
                                      changed_since=True)
                    self._stop(entry, item, "refused: it changed since you made this change; review it again")
                    break
                try:
                    result = self.run(change["route"], actor, change["body"], perms, session)
                except ValidationError as exc:
                    self._stop(entry, item, str(exc))     # the row says failed; its reason as given
                    break
                with self.lock:
                    self.changes = [c for c in self.changes if c["id"] != change["id"]]
                    for secret in SECRET_KEYS:
                        if isinstance(result, dict) and result.get(secret):
                            self.shown_once.setdefault(owner, []).append({"what": change["what"],
                                                                          "secret": result[secret]})
                applied += 1
                touched.add(key)
                # a change done with a warning (a zone published, the resolver not flushed: 2.1.4.9) says it
                self._mark(item, "done", result.get("warning") if isinstance(result, dict) else None)
            if last and applied == len(mine):
                item = entry["items"][-1]
                self._mark(item, "running")
                try:
                    said = last[1](actor)
                    self._mark(item, "done", said if isinstance(said, str) else "")
                except ValidationError as exc:
                    self._stop(entry, item, str(exc))     # the row says failed; its reason as given
        except Exception:                # an unexpected error: the job's error; the queue says so too
            with self.lock:
                entry["state"] = "failed"
                for item in entry["items"]:
                    if item["state"] == "running":
                        item["state"], item["why"] = "failed", "internal error (see the fabric-agent journal)"
                entry["finished"] = time.time()
            raise
        with self.lock:
            if entry["state"] == "running":
                entry["state"] = "done"
            entry["finished"] = time.time()
            for item in entry["items"]:
                if item["state"] == "queued":
                    item["state"], item["why"] = "not run", "an earlier change stopped the apply"
        return {"page": next(iter(mine))["page"], "applied": applied,
                "items": [{k: i[k] for k in ("what", "state", "why")} for i in entry["items"]]}

    def _mark(self, item, state, why=None):
        """Purpose: One queue item's state, under the lock.
        Inputs:  item — a queue item; state — str; why — what its row says (a finish's note, a change's warning), None:
                 unchanged.
        Returns: None.
        Fails:   never.
        Feeds:   _run_all."""
        with self.lock:
            item["state"] = state
            if why is not None:
                item["why"] = why

    def _stop(self, entry, item, why):
        """Purpose: The apply stopped at this change, with why.
        Inputs:  entry — the queue entry; item — the change's item; why — str, the reason as the change or the
                 finish gave it (the row's state already says "failed": no prefix of its own).
        Returns: None.
        Fails:   never.
        Feeds:   _run_all."""
        with self.lock:
            item["state"], item["why"], entry["state"] = "failed", why, "failed"

    def _expire(self):
        """Purpose: Forget finished applies older than QUEUE_SECONDS (called under the lock).
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   page."""
        cut = time.time() - QUEUE_SECONDS
        for page in list(self.queue):
            self.queue[page] = [a for a in self.queue[page] if a["state"] == "running" or a.get("finished", 0) > cut]


def _read(state, route, body):
    """Purpose: Read the thing a change changes, any failure a refusal that says why (fail closed: a change whose thing
             cannot be read is neither held nor run).
    Inputs:  state — the store's reader; route — the change's route; body — its body.
    Returns: the read (dict, list or None).
    Fails:   ValidationError: the reader's own, or "could not read what this change changes now: <why>" for any other
             error (the DC not reachable, a setting missing).
    Feeds:   PendingStore.hold, _run_all."""
    try:
        return state(route, body)
    except ValidationError:
        raise
    except Exception as exc:                  # noqa: BLE001  (every failure is a refusal, said with its why)
        raise ValidationError(f"could not read what this change changes now: {type(exc).__name__}: {exc}") from exc


def _old(state, route, body):
    """Purpose: The old values a change replaces: the thing's fields the body names, as read now, or what an action
             with no fields changes (pending_thing.state_change).
    Inputs:  state — the thing's read (dict, list or None); route — the change's route; body — the change's body.
    Returns: dict (empty for a new thing or an action with no fields).
    Fails:   never.
    Feeds:   PendingStore.hold, _run_all."""
    if not isinstance(state, dict):
        return state_change(route, state)[0]
    return {k: state.get(k) for k in body if k in state and k != "confirm"} or state_change(route, state)[0]


def _new(state, route, body):
    """Purpose: The new values a change sets, as the Review shows them (the typed-back confirmation left out), or what
             an action with no fields changes (pending_thing.state_change).
    Inputs:  state — the thing's read; route — the change's route; body — the change's body.
    Returns: dict.
    Fails:   never.
    Feeds:   PendingStore.hold."""
    return {k: v for k, v in body.items() if k != "confirm"} or state_change(route, state)[1]
