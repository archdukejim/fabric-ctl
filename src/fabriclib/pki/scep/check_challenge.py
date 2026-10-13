import datetime

from fabriclib.common.write_audit import write_audit
from fabriclib.pki.scep.common.challenge_lock import challenge_lock
from fabriclib.pki.scep.common.hash_challenge import hash_challenge
from fabriclib.pki.scep.common.read_challenges import read_challenges
from fabriclib.pki.scep.common.write_challenges import write_challenges
from fabriclib.pki.scep.constants import CHALLENGES_FILE


def _cn_of(body):
    """Purpose: the common name of the request Step-CA is asking about.
    Inputs:  body — the SCEPCHALLENGE webhook's JSON body (x509CertificateRequest.subject.commonName).
    Returns: str, "" when absent.
    Fails:   never.
    Feeds:   check_challenge."""
    req = body.get("x509CertificateRequest") if isinstance(body, dict) else None
    subject = req.get("subject") if isinstance(req, dict) else None
    return str((subject or {}).get("commonName") or "") if isinstance(subject, dict) else ""


def check_challenge(body, store=CHALLENGES_FILE, now=None):
    """Purpose: Step-CA's SCEPCHALLENGE question (manual 1.5.3.4): may this request be signed? A challenge is good once:
             the first time it is asked about it is spent, whatever the answer; refused when unknown, already used,
             withdrawn, expired, or for another name than its profile's. The same transaction asked again after it
             was allowed (a retry) gets the same answer.
    Inputs:  body — the webhook's JSON body: scepChallenge, scepTransactionID, x509CertificateRequest (its subject's
             commonName); store — the challenge store; now — aware datetime for tests.
    Returns: (allow: bool, why: str) — why is "" when allowed. The record gets state "used", used_at, transaction and
             outcome ("allowed" or the refusal). Audited SCEP_CHALLENGE_USED or SCEP_CHALLENGE_REFUSED (with the id,
             never the challenge), as the person who made it ("step-ca" for an unknown one).
    Fails:   OSError / ValueError from the store (the hook then answers an error: Step-CA refuses the request).
    Feeds:   answer_hook (POST /hooks/scep/challenge)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    challenge = str(body.get("scepChallenge") or "") if isinstance(body, dict) else ""
    transaction = str(body.get("scepTransactionID") or "")[:128] if isinstance(body, dict) else ""
    cn = _cn_of(body)
    digest = hash_challenge(challenge) if challenge else None
    with challenge_lock(store):
        items = read_challenges(store)
        rec = next((c for c in items if digest and c.get("hash") == digest), None)
        if rec is None:
            why = "no such challenge" if challenge else "the request carries no challenge"
        elif rec.get("state") == "used":
            # the same request asked again (Step-CA retries a call once; a client resends its transaction): the
            # answer it got, never a second request
            repeat = (rec.get("outcome") == "allowed" and transaction and rec.get("transaction") == transaction
                      and cn == rec.get("cn"))
            why = "" if repeat else "the challenge was already used"
        elif rec.get("state") == "withdrawn":
            why = "the challenge was withdrawn"
        elif datetime.datetime.fromisoformat(rec["expires"]) <= now:
            why = "the challenge expired"
        elif cn != rec.get("cn"):
            why = f"the request's name {cn!r} is not the profile's ({rec.get('cn')})"
        else:
            why = ""
        if rec is not None and rec.get("state") == "open":            # spent on first use, whatever the answer
            rec.update({"state": "used", "used_at": now.isoformat(timespec="seconds"), "transaction": transaction,
                        "outcome": why or "allowed"})
            write_challenges(store, items, now=now)
    actor = rec.get("by", "step-ca") if rec else "step-ca"
    cid = rec.get("id", "-") if rec else "-"
    if why:
        write_audit(actor, "SCEP_CHALLENGE_REFUSED", f"id={cid} name={cn or '-'}: {why}", "scep")
    else:
        write_audit(actor, "SCEP_CHALLENGE_USED", f"id={cid} name={cn} transaction={transaction}", "scep")
    return not why, why
