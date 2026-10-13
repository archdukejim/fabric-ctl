"""A site's id block checked before the DC writes anything (decision 2.1.6.46, manual 1.6.3.17; the one-run block of
an install from before 0.7.0 deleted, S11): src/containers/samba/id_layout.check_block. Pure logic, no container.
    python3 tests/samba/id_layout_test.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "containers", "samba"))
from id_layout import RANGES, check_block  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def refused(block):
    try:
        check_block(block)
    except ValueError as e:
        return str(e)
    return None


check("the root's block, site 1's", check_block("1000000-1999999") == (1000000, 1999999))
check("site 999's block, the last", check_block("999000000-999999999") == (999000000, 999999999))
check("every fixed range fits a block", all(0 <= lo <= hi < 1_000_000 for lo, hi in RANGES.values()))
for bad, said in (("5001-105000", "not a site's block"), ("200001-300000", "not a site's block"),
                  ("900-908", "not a site's block"), ("1000000-1099999", "not a site's block"),
                  ("0-999999", "not a site's block"), ("1000000", "two whole numbers"), ("a-b", "two whole numbers"),
                  ("", "two whole numbers")):
    why = refused(bad)
    check(f"refused: {bad!r} ({said}), naming the block", why and said in why and repr(bad) in why, why)

print(f"\nid_layout: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
