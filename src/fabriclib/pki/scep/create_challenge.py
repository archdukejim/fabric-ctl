import datetime
import secrets

from fabriclib.common.write_audit import write_audit
from fabriclib.pki.scep.common.challenge_lock import challenge_lock
from fabriclib.pki.scep.common.hash_challenge import hash_challenge
from fabriclib.pki.scep.common.read_challenges import read_challenges
from fabriclib.pki.scep.common.write_challenges import write_challenges
from fabriclib.pki.scep.constants import CHALLENGES_FILE, DEFAULT_MINUTES


def create_challenge(v, actor, cn, device="", source="web", store=CHALLENGES_FILE, now=None):
    """Purpose: a one-time SCEP challenge for one Apple profile (manual 1.5.3.4): random, good for one request within
             scep_challenge_minutes, for the name the profile asks for, bound to the person who made it; only its
             SHA-256 is kept.
    Inputs:  v — settings (scep_challenge_minutes, checked at apply; default 60); actor — the person (audit, store);
             cn — the certificate name the profile asks for (checked by the caller); device — the device to link, or
             ""; source — the audit's; store — the challenge store; now — aware datetime for tests.
    Returns: {"challenge" (32 characters, shown nowhere but in the profile), "id", "expires" (ISO, UTC)}.
    Fails:   OSError / ValueError from the store (a damaged store refuses, never starts over); OSError from the audit.
    Feeds:   enrol_apple."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    minutes = int(v.get("scep_challenge_minutes") or DEFAULT_MINUTES)
    challenge = secrets.token_urlsafe(24)                       # 192 bits, 32 characters
    cid = secrets.token_hex(8)
    expires = now + datetime.timedelta(minutes=minutes)
    record = {"id": cid, "hash": hash_challenge(challenge), "by": actor, "made": now.isoformat(timespec="seconds"),
              "expires": expires.isoformat(timespec="seconds"), "cn": cn, "device": device, "state": "open"}
    with challenge_lock(store):
        items = read_challenges(store)
        items.append(record)
        write_challenges(store, items, now=now)
    write_audit(actor, "SCEP_CHALLENGE", f"id={cid} name={cn} device={device or '-'} until={record['expires']}",
                source)
    return {"challenge": challenge, "id": cid, "expires": record["expires"]}
