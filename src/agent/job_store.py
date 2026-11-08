import itertools
import secrets
import threading
import time
import traceback

from agent.kept_store import KEPT
from fabriclib.common.errors import ValidationError

KEEP = 50                                     # finished jobs kept for their pages, newest first


class JobStore:
    """Purpose: the agent's background jobs (manual 1.3.3, 2.1.8.3): work that takes longer than a request (doctor,
             an image update), started by one call and followed by its id. In memory: an agent restart forgets them.
    Feeds:   agent/post_route (POST /v1/jobs/<kind>), agent/get_route (GET /v1/jobs/<id>)."""

    def __init__(self):
        """Purpose: an empty store.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   JOBS (one per agent process)."""
        self.lock = threading.Lock()
        self.jobs = {}
        self.order = itertools.count()

    def start(self, kind, owner, fn):
        """Purpose: run fn in a thread of its own and remember its outcome.
        Inputs:  kind — str ("doctor", "images"); owner — the user who started it (only they read it; None for root);
                 fn — callable with no arguments returning a JSON-able result.
        Returns: {"id"} — an unguessable id.
        Fails:   never (fn's errors become the job's error).
        Feeds:   post_route."""
        job_id = secrets.token_urlsafe(12)
        job = {"id": job_id, "kind": kind, "owner": owner, "state": "running", "started": time.time(),
               "result": None, "error": "", "n": next(self.order)}
        with self.lock:
            self.jobs[job_id] = job
            for old in sorted((j for j in self.jobs.values() if j["state"] != "running"), key=lambda j: j["n"])[
                    :-KEEP]:
                del self.jobs[old["id"]]

        def run():
            try:
                result, state, error = fn(), "done", ""
            except ValidationError as exc:
                result, state, error = None, "failed", str(exc)
            except Exception:                 # the journal gets the traceback; the page a plain message
                traceback.print_exc()
                result, state, error = None, "failed", "internal error (see the fabric-agent journal)"
            with self.lock:
                job.update(result=result, state=state, error=error, finished=time.time())
            if kind != "doctor":              # an apply or an update has changed what kept reads show (1.8.9.2)
                KEPT.invalidate()

        threading.Thread(target=run, daemon=True, name=f"job-{kind}").start()
        return {"id": job_id}

    def read(self, job_id, user):
        """Purpose: one job as its owner sees it.
        Inputs:  job_id — str; user — the caller (None for root, who reads any).
        Returns: {"id", "kind", "state" (running|done|failed), "started", "result", "error"}.
        Fails:   ValidationError "no such job" for an unknown id or another person's job (no difference shown).
        Feeds:   get_route."""
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or (user is not None and job["owner"] != user):
                raise ValidationError("no such job")
            return {k: job[k] for k in ("id", "kind", "state", "started", "result", "error")}


JOBS = JobStore()
