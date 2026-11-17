#!/usr/bin/env python3
"""Split DNS needs the DNS filter (decision 2.1.4.16, manual 1.4.1.11): with the filter on, or with no record for one
VLAN, nothing is refused; with it off and a record for one VLAN, refused, naming the records and why; a change checked
before it is saved (the filter's setting given); unset counts as on. Pure logic; no container.

    python3 tests/dns/split/split_needs_filter_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns.split.split_needs_filter import split_names, split_needs_filter  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def refused(fn, words):
    try:
        fn()
    except ValidationError as e:
        return words in str(e) or str(e)
    return "not refused"


SPLIT = {"dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"},
                                            {"name": "nas", "ip": "10.1.20.10", "vlan": "20"}],
                                      "CNAME": [{"name": "files", "canonical": "nas", "vlan": "20@branch"}]}}}
PLAIN = {"dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"}]}}}

check("split_names: each record for one VLAN, named with its VLAN",
      split_names(SPLIT) == ["nas (VLAN 20)", "files (VLAN 20@branch)"], split_names(SPLIT))
check("split_names: none without a VLAN, nor with no dns at all",
      split_names(PLAIN) == [] and split_names({}) == [] and split_names({"dns": None}) == [])
check("positive: the filter on and records for one VLAN: nothing refused",
      split_needs_filter({**SPLIT, "dns_filter": "bind"}) is None)
check("positive: the filter unset counts as on", split_needs_filter(SPLIT) is None)
check("positive: the filter off and no record for one VLAN: nothing refused",
      split_needs_filter({**PLAIN, "dns_filter": "none"}) is None)
check("negative: the filter off with records for one VLAN: refused, saying why",
      refused(lambda: split_needs_filter({**SPLIT, "dns_filter": "none"}), "needs the DNS filter on") is True)
check("negative: the refusal names the records",
      refused(lambda: split_needs_filter({**SPLIT, "dns_filter": "none"}), "nas (VLAN 20), files (VLAN 20@branch)")
      is True)
check("negative: a change turning the filter off is checked before it is saved",
      refused(lambda: split_needs_filter({**SPLIT, "dns_filter": "bind"}, "none"), "Windows domain") is True)
check("positive: a change turning the filter on is not refused",
      split_needs_filter({**SPLIT, "dns_filter": "none"}, "bind") is None)
MANY = {"dns": {"z": {"A": [{"name": f"h{i}", "ip": "10.0.0.1", "vlan": "20"} for i in range(7)]}}, "dns_filter": "none"}
check("negative: many records: five named, the rest counted",
      refused(lambda: split_needs_filter(MANY), "h4 (VLAN 20) and 2 more") is True)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
