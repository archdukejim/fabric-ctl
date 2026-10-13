import json
import os


def read_challenges(store):
    """Purpose: the challenge store: every one-time challenge made for an Apple profile, by its SHA-256 only.
    Inputs:  store — path of the store (JSON list; missing means none yet).
    Returns: list of dicts {id, hash, by, made, expires, cn, device, state (open | used | withdrawn), and once used:
             used_at, transaction, outcome; once issued: serial, link_error}.
    Fails:   OSError other than a missing file; ValueError (json) on a damaged store — never read as empty, which
             would make spent challenges look unknown rather than refusing loudly.
    Feeds:   create_challenge, check_challenge, record_scep_issue, withdraw_challenge, list_enrolments."""
    if not os.path.exists(store):
        return []
    with open(store) as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{store}: not a list of challenges")
    return data
