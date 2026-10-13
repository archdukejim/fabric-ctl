import datetime
import json
import os

KEEP_DAYS = 90          # finished challenges older than this are dropped; the audit keeps their story


def write_challenges(store, items, now=None):
    """Purpose: save the challenge store atomically, root-only, without the challenges finished long ago.
    Inputs:  store — path; items — list of challenge dicts (read_challenges' form); now — aware datetime for tests.
    Returns: None; the file is replaced (0600, its folder 0700). Open challenges are always kept; used, withdrawn and
             expired ones only for KEEP_DAYS after they were made.
    Fails:   OSError writing; ValueError on a record whose made is not an ISO date.
    Feeds:   create_challenge, check_challenge, record_scep_issue, withdraw_challenge."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=KEEP_DAYS)
    kept = [c for c in items if c.get("state") == "open" and datetime.datetime.fromisoformat(c["expires"]) > now
            or datetime.datetime.fromisoformat(c["made"]) > cutoff]
    os.makedirs(os.path.dirname(store), mode=0o700, exist_ok=True)
    tmp = store + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(kept, f, indent=1)
    os.replace(tmp, store)
