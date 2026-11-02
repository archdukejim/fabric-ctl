#!/usr/bin/env python3
"""Kea's DNS key: when an apply replaces it and how (decision 2.1.10.42, manual 1.10.4.43): dated at the first apply
that sees it, replaced from day 330 (or when asked), the old key kept for BIND until Kea runs on the new, nothing
started while a replacement is under way or with Kea's registration off. Pure logic.

    python3 tests/dhcp/kea_key/start_key_rotation_test.py
"""
import datetime
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.dhcp.kea_key.kea_key import kea_key  # noqa: E402
from fabriclib.dhcp.kea_key.start_key_rotation import start_key_rotation  # noqa: E402

FAILED = 0
V = {"install_kea": True, "dhcp": {"ddns": True}}
TODAY = datetime.date(2026, 10, 24)


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def made(days):
    return (TODAY - datetime.timedelta(days=days)).isoformat()


s = {"kea_ddns_secret": "c2VjcmV0"}
out = start_key_rotation(V, s, today=TODAY)
check("a key made before 0.9.0 (not dated): dated today, kept; the secrets to save", out == {"changed": True,
      "started": None} and s == {"kea_ddns_secret": "c2VjcmV0", "kea_ddns_made": "2026-10-24"}, (out, s))
s = {"kea_ddns_secret": "c2VjcmV0", "kea_ddns_made": made(329)}
out = start_key_rotation(V, s, today=TODAY)
check("329 days old: kept, nothing to save", out == {"changed": False, "started": None}
      and "kea_ddns_old" not in s, (out, s))
s = {"kea_ddns_secret": "c2VjcmV0", "kea_ddns_made": made(330)}
out = start_key_rotation(V, s, today=TODAY)
key = kea_key(s, TODAY)
check("330 days old: replaced: a new name and a new 256-bit secret are Kea's, dated today; the old kept for BIND",
      out["changed"] and key["name"] == "kea-ddns-20261024" and len(key["secret"]) == 44
      and key["secret"] != "c2VjcmV0" and key["age"] == 0
      and key["old"] == {"name": "kea-ddns", "secret": "c2VjcmV0", "made": made(330)}
      and "330 days old" in out["started"] and "kea-ddns-20261024" in out["started"], (out, s))
before = dict(s)
out = start_key_rotation(V, s, today=TODAY, force=True)
check("a replacement under way: nothing started (that apply finishes it), even when asked", out == {
      "changed": False, "started": None} and s == before, (out, s))
s = {"kea_ddns_secret": "c2VjcmV0", "kea_ddns_made": made(400)}
out = start_key_rotation(V, s, due=False, today=TODAY)
check("not this run's to replace (setup's first deploy, DNS' own Apply): kept however old", out["started"] is None
      and "kea_ddns_old" not in s, (out, s))
s = {"kea_ddns_secret": "c2VjcmV0", "kea_ddns_made": made(10), "kea_ddns_key": "kea-ddns-20261024"}
out = start_key_rotation(V, s, force=True, today=TODAY)
check("asked for (rotate-key) whatever its age; a second one on the same day takes a name of its own",
      s["kea_ddns_key"] == "kea-ddns-20261024-2" and s["kea_ddns_old"]["name"] == "kea-ddns-20261024"
      and "asked for" in out["started"], (out, s))
for name, v in (("DHCP off", {"install_kea": False}), ("Kea registering no names", {"install_kea": True,
                                                                                    "dhcp": {"ddns": False}})):
    s = {"kea_ddns_secret": "c2VjcmV0", "kea_ddns_made": made(400)}
    out = start_key_rotation(v, s, force=True, today=TODAY)
    check(f"{name}: no key to replace, nothing changed", out == {"changed": False, "started": None}
          and "kea_ddns_old" not in s, out)
s = {}
check("no key made yet (no apply ran): nothing", start_key_rotation(V, s, force=True, today=TODAY)
      == {"changed": False, "started": None} and s == {})
check("a made date that does not read counts as not dated", kea_key({"kea_ddns_made": "soon"}, TODAY)["age"] is None)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
