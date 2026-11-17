#!/usr/bin/env python3
"""An A or AAAA record's aliases in its own zone (decision 2.1.4.14, manual 1.4.1.9.4): every CNAME pointing at it,
chains included, relative and absolute targets; a CNAME into another zone, a chain leaving the zone, a loop and a
wildcard are not aliases. Also what a key's records_with_aliases grants at a render (alias_grants), the choices a key's
names are picked from (key_record_choices) and the mode a key shows (tsig_key_mode). Pure logic; no container (BIND's
side is the zones suite).

    python3 tests/dns/record_aliases_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns.alias_grants import alias_grants  # noqa: E402
from fabriclib.dns.key_record_choices import key_record_choices  # noqa: E402
from fabriclib.dns.record_aliases import record_aliases  # noqa: E402
from fabriclib.dns.tsig_key_mode import tsig_key_mode  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


ZONE = {"A": [{"name": "proxy", "ip": "10.0.0.5"}, {"name": "nas", "ip": "10.0.0.6"}, {"name": "@", "ip": "10.0.0.1"}],
        "AAAA": [{"name": "v6host", "ip": "fd00::6"}],
        "CNAME": [{"name": "web", "canonical": "proxy"},                        # relative
                  {"name": "git", "canonical": "proxy.lan.test."},              # absolute, in the zone
                  {"name": "wiki", "canonical": "web"},                         # a chain: wiki -> web -> proxy
                  {"name": "docs", "canonical": "wiki.lan.test."},              # a longer chain
                  {"name": "away", "canonical": "proxy.other.test."},           # another zone's proxy
                  {"name": "loop1", "canonical": "loop2"}, {"name": "loop2", "canonical": "loop1"},
                  {"name": "*.apps", "canonical": "proxy"},                     # a wildcard
                  {"name": "files", "canonical": "nas"},
                  {"name": "six", "canonical": "v6host"},
                  {"name": "apex", "canonical": "lan.test."}]}

got = record_aliases(ZONE, "lan.test", "proxy")
check("an A record's aliases: relative and absolute targets, and chains (two and three steps)",
      got == ["docs", "git", "web", "wiki"], got)
check("a CNAME to another zone's name of the same label is not an alias", "away" not in got, got)
check("a wildcard is never an alias", "*.apps" not in got, got)
check("an AAAA record has aliases too", record_aliases(ZONE, "lan.test", "v6host") == ["six"])
check("the record's name compared without case", record_aliases(ZONE, "lan.test", "PROXY") == got)
check("a CNAME is not an address: no aliases", record_aliases(ZONE, "lan.test", "web") == [])
check("a name not in the zone: no aliases", record_aliases(ZONE, "lan.test", "ghost") == [])
check("a loop is cut, never granted", record_aliases(ZONE, "lan.test", "loop1") == [])
check("the zone's own name (@) as a target: an alias of @, which is not offered",
      record_aliases(ZONE, "lan.test", "@") == ["apex"])

DATA = {"domain": "lan.test", "dns": {"dynamic_zone_var": ZONE, "home.lan": {"A": [{"name": "tv", "ip": "10.1.0.2"}],
                                                                             "CNAME": [{"name": "proxy",
                                                                                        "canonical": "tv"}]}},
        "tsig_keys": [{"name": "npm", "domain": "lan.test", "records_with_aliases": ["proxy", "gone"],
                       "record_types": ["TXT"]},
                      {"name": "home", "domain": "home.lan", "records_with_aliases": ["tv"], "record_types": ["TXT"]},
                      {"name": "plain", "domain": "lan.test", "records": ["nas"], "record_types": ["TXT"]}]}
grants = alias_grants(DATA)
check("alias_grants: each entry's record and its aliases as the zone is now",
      grants["npm"]["proxy"] == ["proxy", "docs", "git", "web", "wiki"], grants)
check("alias_grants: a record no longer an A or AAAA of the zone covers nothing", grants["npm"]["gone"] == [], grants)
check("alias_grants: a key of another zone sees that zone only (its proxy alias, not lan.test's)",
      grants["home"]["tv"] == ["tv", "proxy"], grants)
check("alias_grants: a key without entries is not listed", "plain" not in grants, grants)
DATA["dns"]["dynamic_zone_var"]["CNAME"].append({"name": "late", "canonical": "proxy"})
check("alias_grants: a CNAME made later is granted at the next render (the aliases follow the zone)",
      "late" in alias_grants(DATA)["npm"]["proxy"])
DATA["dns"]["dynamic_zone_var"]["CNAME"] = [c for c in DATA["dns"]["dynamic_zone_var"]["CNAME"] if c["name"] != "git"]
check("alias_grants: a CNAME removed loses its grant at the next render", "git" not in alias_grants(DATA)["npm"]["proxy"])

choices = key_record_choices(DATA, "lan.test")
by = {c["name"]: c for c in choices}
check("choices: A, AAAA and CNAME names once each, @ and wildcards left out",
      "@" not in by and "*.apps" not in by and by["proxy"]["types"] == ["A"] and by["web"]["types"] == ["CNAME"], by)
check("choices: an address offers its aliases; a CNAME none",
      by["proxy"]["address"] and "web" in by["proxy"]["aliases"] and not by["web"]["address"]
      and by["web"]["aliases"] == [], by)
try:
    key_record_choices(DATA, "nowhere.test")
    check("choices: an unknown zone is refused", False)
except ValidationError as e:
    check("choices: an unknown zone is refused, naming it", "nowhere.test" in str(e), e)

check("mode: records and records with aliases of the zone, TXT only -> ACME",
      tsig_key_mode({"records": ["web"], "records_with_aliases": ["proxy"], "record_types": ["TXT"]}, choices)
      == "acme")
for why, key in (("a name not in the zone", {"records": ["printer"], "record_types": ["TXT"]}),
                 ("a type other than TXT", {"records": ["web"], "record_types": ["TXT", "A"]}),
                 ("any name", {"any_name": True, "record_types": ["TXT"]}),
                 ("the zone's challenge names (primary)", {"primary": True, "record_types": ["TXT"]}),
                 ("a CNAME picked with aliases", {"records_with_aliases": ["web"]}),
                 ("no names", {"record_types": ["TXT"]})):
    check(f"mode: {why} -> Custom", tsig_key_mode(key, choices) == "custom", key)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
