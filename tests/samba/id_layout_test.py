"""A DC's id range (decisions 2.1.6.46, 2.1.6.63, 2.1.6.86; manual 1.6.3.17): src/containers/samba/id_layout's dc_range
(a DC's range from its name) and check_block (a range a DC's record holds, checked before the DC writes anything). Pure
logic, no container.
    python3 tests/samba/id_layout_test.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "containers", "samba"))
from id_layout import RANGES, check_block, dc_range  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def refused(fn, value):
    try:
        fn(value)
    except ValueError as e:
        return str(e)
    return None


check("dc-0001's range, the root's first DC's", dc_range("dc-0001") == "1000000-1999999")
check("a DC's range is its number's, any case: DC-0042", dc_range("DC-0042") == "42000000-42999999")
check("dc-1999's range, the last, ends below 2000000000", dc_range("dc-1999") == "1999000000-1999999999")
for bad in ("dc1", "dc-pi", "dc-0000", "dc-2000", "dc-001", "dc-00001", "", None):
    why = refused(dc_range, bad)
    check(f"refused: the DC name {bad!r} (not dc-0001 to dc-1999), saying to install 0.8.0 fresh (2.1.1.60)",
          why and "numbered names" in why and "install it fresh" in why and "3.3.5" in why, why)
check("a DC's range passes the record check", check_block("1000000-1999999") == (1000000, 1999999)
      and check_block(dc_range("dc-1999")) == (1999000000, 1999999999))
check("every fixed range fits a DC's range", all(0 <= lo <= hi < 1_000_000 for lo, hi in RANGES.values()))
for bad, said in (("5001-105000", "not a DC's"), ("200001-300000", "not a DC's"),
                  ("900-908", "not a DC's"), ("1000000-1099999", "not a DC's"),
                  ("0-999999", "not a DC's"), ("2000000000-2000999999", "not a DC's"),
                  ("1000000", "two whole numbers"), ("a-b", "two whole numbers"), ("", "two whole numbers")):
    why = refused(check_block, bad)
    check(f"refused: the range {bad!r} ({said}), naming it", why and said in why and repr(bad) in why, why)

print(f"\nid_layout: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
