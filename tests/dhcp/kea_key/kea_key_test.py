#!/usr/bin/env python3
"""Kea's DNS key as fabric's secrets hold it (decision 2.1.10.42, manual 1.10.4.43): its name (the install's
"kea-ddns" until first replaced), its age in days, the key being replaced. Pure logic.

    python3 tests/dhcp/kea_key/kea_key_test.py
"""
import datetime
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.dhcp.kea_key.kea_key import kea_key  # noqa: E402

FAILED = 0
TODAY = datetime.date(2026, 10, 24)


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


out = kea_key({"kea_ddns_secret": "c2VjcmV0", "kea_ddns_made": "2026-01-01"}, TODAY)
check("the install's key: named kea-ddns, its age in whole days, none being replaced",
      out == {"name": "kea-ddns", "secret": "c2VjcmV0", "made": "2026-01-01", "age": 296, "old": None}, out)
old = {"name": "kea-ddns", "secret": "b2xk", "made": "2025-11-28"}
out = kea_key({"kea_ddns_key": "kea-ddns-20261024", "kea_ddns_secret": "bmV3", "kea_ddns_made": "2026-10-24",
               "kea_ddns_old": old}, TODAY)
check("a replaced key: its own name, age 0, the old one kept", out["name"] == "kea-ddns-20261024"
      and out["age"] == 0 and out["old"] == old, out)
out = kea_key({}, TODAY)
check("nothing made yet: the default name, no secret, not dated", out == {"name": "kea-ddns", "secret": "",
      "made": None, "age": None, "old": None}, out)
out = kea_key({"kea_ddns_made": "2026-13-40"}, TODAY)
check("a date that does not read: not dated", out["made"] is None and out["age"] is None, out)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
