#!/usr/bin/env python3
"""Split DNS needs the DNS filter (decisions 2.1.4.16, 2.1.4.18; manual 1.4.1.13): with the filter on, or with no
zone mapped or split, nothing is refused; with it off and a zone mapped or split, refused, naming the zones and why;
a change checked before it is saved (the filter's setting given); unset counts as on. Pure logic; no container.

    python3 tests/dns/split/split_needs_filter_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns.split.split_needs_filter import split_needs_filter, split_zones  # noqa: E402

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


SPLIT = {"domain": "home.arpa",
         "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"}],
                                      "splits": [{"subnets": ["10.1.20.0/24"]}, {"subnets": ["10.1.21.0/24"]}]},
                 "iot.lan": {"networks": ["10.1.20.0/24"], "splits": [{"subnets": ["10.1.20.0/24"]}]},
                 "plain.lan": {"A": []}}}
PLAIN = {"dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"}]}}}

check("split_zones: each zone mapped or split, named with what it has, the site's own by its name",
      split_zones(SPLIT) == ["home.arpa (2 splits)", "iot.lan (mapped, 1 split)"], split_zones(SPLIT))
check("split_zones: none for zones answering every network with no split, nor with no dns at all",
      split_zones(PLAIN) == [] and split_zones({}) == [] and split_zones({"dns": None}) == [])
check("positive: the filter on and zones split: nothing refused", split_needs_filter({**SPLIT, "dns_filter": "bind"})
      is None)
check("positive: the filter unset counts as on", split_needs_filter(SPLIT) is None)
check("positive: the filter off and no zone mapped or split: nothing refused",
      split_needs_filter({**PLAIN, "dns_filter": "none"}) is None)
check("negative: the filter off with zones split: refused, saying why",
      refused(lambda: split_needs_filter({**SPLIT, "dns_filter": "none"}), "needs the DNS filter on") is True)
check("negative: the refusal names the zones",
      refused(lambda: split_needs_filter({**SPLIT, "dns_filter": "none"}),
              "home.arpa (2 splits), iot.lan (mapped, 1 split)") is True)
check("negative: a change turning the filter off is checked before it is saved",
      refused(lambda: split_needs_filter({**SPLIT, "dns_filter": "bind"}, "none"), "Windows domain") is True)
check("positive: a change turning the filter on is not refused",
      split_needs_filter({**SPLIT, "dns_filter": "none"}, "bind") is None)
MANY = {"dns": {f"z{i}.lan": {"networks": ["10.0.0.0/24"]} for i in range(7)}, "dns_filter": "none"}
check("negative: many zones: five named, the rest counted",
      refused(lambda: split_needs_filter(MANY), "z4.lan (mapped) and 2 more") is True)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
