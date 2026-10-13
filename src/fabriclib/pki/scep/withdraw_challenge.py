import datetime

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.pki.scep.common.challenge_lock import challenge_lock
from fabriclib.pki.scep.common.read_challenges import read_challenges
from fabriclib.pki.scep.common.write_challenges import write_challenges
from fabriclib.pki.scep.constants import CHALLENGES_FILE


def withdraw_challenge(actor, cid, may_withdraw_any=False, source="web", store=CHALLENGES_FILE, now=None):
    """Purpose: withdraw an Apple profile's one-time challenge before it is used (manual 1.5.3.7): nothing can be
             enrolled with it afterwards.
    Inputs:  actor — who asks; cid — the challenge's id; may_withdraw_any — True when actor holds pki:revoke (or is
             root): anyone's; otherwise only actor's own; source — the audit's; store — the challenge store; now —
             aware datetime for tests.
    Returns: {"id", "cn"}.
    Fails:   ValidationError: no such challenge; another person's without pki:revoke; already used, withdrawn or
             expired. OSError / ValueError from the store.
    Feeds:   agent/post_enrol (POST /v1/pki/enrolments/<id>/withdraw)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    with challenge_lock(store):
        items = read_challenges(store)
        rec = next((c for c in items if c.get("id") == str(cid)), None)
        if rec is None:
            raise ValidationError(f"no open profile {cid!r}")
        if rec.get("by") != actor and not may_withdraw_any:
            raise ValidationError("only the person who made a profile, or someone with pki:revoke, may withdraw it")
        if rec.get("state") != "open" or datetime.datetime.fromisoformat(rec["expires"]) <= now:
            raise ValidationError(f"profile {cid} can no longer be used (it was {rec.get('state')} or expired): "
                                  "nothing to withdraw")
        rec.update({"state": "withdrawn", "used_at": now.isoformat(timespec="seconds"), "outcome": f"withdrawn by "
                                                                                                  f"{actor}"})
        write_challenges(store, items, now=now)
    write_audit(actor, "SCEP_CHALLENGE_WITHDRAWN", f"id={cid} name={rec.get('cn')} made by {rec.get('by')}", source)
    return {"id": rec["id"], "cn": rec.get("cn", "")}
