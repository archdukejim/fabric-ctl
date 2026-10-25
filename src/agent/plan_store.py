import secrets
import threading
import time

from fabriclib.common.errors import ValidationError
from fabriclib.settings.constants import PLAN_TTL

KEEP = 50                                     # plans kept at most, newest first


class PlanStore:
    """Purpose: the setup wizard's plans waiting for their Apply (manual 1.8.5.5): made by POST /v1/settings/plan,
             applied by id with POST /v1/settings/apply, only by the person who made it, within PLAN_TTL. In memory:
             an agent restart forgets them (the plan is made again).
    Feeds:   agent/post_settings."""

    def __init__(self):
        """Purpose: an empty store.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   PLANS (one per agent process)."""
        self.lock = threading.Lock()
        self.plans = {}

    def put(self, owner, plan):
        """Purpose: keep a plan for its Apply.
        Inputs:  owner — the user who made it (None for root); plan — plan_settings' result.
        Returns: the plan with "id" (unguessable) added.
        Fails:   never.
        Feeds:   post_settings (plan, and a stale plan made again)."""
        plan = {**plan, "id": secrets.token_urlsafe(12)}
        now = time.time()
        with self.lock:
            for pid in [p for p, rec in self.plans.items() if now - rec["at"] > PLAN_TTL]:
                del self.plans[pid]
            for pid in sorted(self.plans, key=lambda p: self.plans[p]["at"])[:-KEEP]:
                del self.plans[pid]
            self.plans[plan["id"]] = {"owner": owner, "plan": plan, "at": now}
        return plan

    def take(self, plan_id, owner):
        """Purpose: a plan for its Apply, removed from the store (a plan is applied once).
        Inputs:  plan_id — str; owner — the caller (None for root, who may take any).
        Returns: the plan.
        Fails:   ValidationError "no such plan …" for an unknown or expired id, or another person's plan (no difference
                 shown).
        Feeds:   post_settings (apply)."""
        with self.lock:
            rec = self.plans.get(str(plan_id))
            if (not rec or time.time() - rec["at"] > PLAN_TTL
                    or (owner is not None and rec["owner"] != owner)):
                raise ValidationError("no such plan (it expired after 15 minutes, or was applied): review the "
                                      "settings again")
            del self.plans[str(plan_id)]
            return rec["plan"]


PLANS = PlanStore()
