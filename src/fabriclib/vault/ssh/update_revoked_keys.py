import json
import os

from fabriclib.vault.ssh.constants import REVOKED_STORE


def update_revoked_keys(config_dir, add, cleared, now):
    """Purpose: the host keys clients must refuse (manual 1.6.11.9.12): each key whose certificate fabric withdrew
             before it ran out stays revoked until that certificate would have expired, then is dropped; a key
             fabric signs again (its machine managed again) is cleared at once, since an @revoked key is refused
             even with a new certificate. Kept in REVOKED_STORE in the install's config folder (root, 0600).
    Inputs:  config_dir — the install's config folder; add — list of {"key" ("<type> <base64>"), "until" (int,
             the withdrawn certificate's end), "name"}; cleared — set of key lines signed now; now — int seconds.
    Returns: list of key lines still revoked, sorted.
    Fails:   OSError writing the store (an unreadable or damaged store counts as empty and is rewritten).
    Feeds:   vault/ssh/sign_ssh_hosts."""
    path = os.path.join(config_dir, REVOKED_STORE)
    try:
        with open(path) as f:
            raw = json.load(f)
        have = [e for e in raw if isinstance(e, dict) and e.get("key")] if isinstance(raw, list) else []
        damaged = not isinstance(raw, list) or len(have) != len(raw)
    except (OSError, ValueError):
        have, damaged = [], True
    by_key = {}
    for e in have + list(add):
        key = " ".join(str(e["key"]).split()[:2])
        until = int(e.get("until") or 0)
        if until > now and key not in cleared and until >= by_key.get(key, {}).get("until", 0):
            by_key[key] = {"key": key, "until": until, "name": str(e.get("name") or "")}
    out = sorted(by_key.values(), key=lambda e: e["key"])
    if damaged or out != sorted(have, key=lambda e: e.get("key", "")):
        os.makedirs(config_dir, exist_ok=True)
        fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(out, f, indent=1)
        os.replace(path + ".new", path)
    return [e["key"] for e in out]
