#!/usr/bin/env python3
"""What `fabricctl doctor` says of Kea's DNS key (decision 2.1.10.42, manual 1.10.4.43): reminders from day 300, due
from day 330, a failed check past the STIG's year, a replacement under way said. Pure logic.

    python3 tests/dhcp/kea_key/key_reminders_test.py
"""
import datetime
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.dhcp.kea_key.key_reminders import key_reminders  # noqa: E402

FAILED = 0
V = {"install_kea": True}
TODAY = datetime.date(2026, 10, 24)


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def at(days, **more):
    return key_reminders(V, {"kea_ddns_secret": "x", "kea_ddns_made": (TODAY - datetime.timedelta(days=days))
                             .isoformat(), **more}, TODAY)


out = at(299)
check("299 days old: the check passes, no reminder", out["checks"][0][1] is True and out["warnings"] == []
      and "299 days old" in out["checks"][0][2], out)
out = at(300)
check("from day 300: reminded, naming rotate-key; the check still passes", out["checks"][0][1] is True
      and "300 days old" in out["warnings"][0] and "rotate-key" in out["warnings"][0]
      and "from day 330" in out["warnings"][0], out)
out = at(331)
check("from day 330: due, the next apply replaces it", "due" in out["warnings"][0], out)
out = at(366)
check("past the STIG's year (no apply ran): the check fails, saying how to replace it now",
      out["checks"][0][1] is False and "rotate-key" in out["checks"][0][2], out)
out = at(0, kea_ddns_key="kea-ddns-20261024", kea_ddns_old={"name": "kea-ddns", "secret": "y", "made": "2025-01-01"})
check("a replacement under way: said, both names, the next apply finishes it; the check passes",
      out["checks"][0][1] is True and "kea-ddns is being replaced by kea-ddns-20261024" in out["warnings"][0]
      and "next apply" in out["warnings"][0], out)
out = key_reminders(V, {"kea_ddns_secret": "x"}, TODAY)
check("not dated yet: said; the check passes", out["checks"][0][1] is True and "not dated" in out["warnings"][0], out)
check("Kea off, or registering no names: nothing said", key_reminders({"install_kea": False}, {}, TODAY)
      == {"checks": [], "warnings": []} and key_reminders({"install_kea": True, "dhcp": {"ddns": False}}, {}, TODAY)
      == {"checks": [], "warnings": []})

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
