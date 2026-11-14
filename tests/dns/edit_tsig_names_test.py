#!/usr/bin/env python3
"""A TSIG key's names edited, its secret, zone and algorithm kept (decisions 2.1.4.13 and 2.1.4.14, manual 1.4.1.9.1
and 1.4.1.9.3): names added and removed one at a time, a record with its aliases added and removed whole, a Custom
key's scope and record types; every refusal says why and changes nothing. Also an ACME key's grant dropped with its
record (drop_removed_names) and following a rename (rename_tsig_names), decision 2.1.4.12. Pure logic on a vars
dict; the units that save it and BIND's side are the zones and webui suites.

    python3 tests/dns/edit_tsig_names_test.py
"""
import copy
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns.drop_removed_names import drop_removed_names  # noqa: E402
from fabriclib.dns.edit_tsig_names import edit_tsig_names  # noqa: E402
from fabriclib.dns.rename_tsig_names import rename_tsig_names  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


DATA = {"domain": "lan.test",
        "dns": {"dynamic_zone_var": {"A": [{"name": "proxy", "ip": "10.0.0.5"}, {"name": "nas", "ip": "10.0.0.6"},
                                           {"name": "pi-core", "ip": "10.0.0.2"}],
                                     "CNAME": [{"name": "web", "canonical": "proxy"},
                                               {"name": "git", "canonical": "proxy"}]}},
        "tsig_keys": [{"name": "npm", "domain": "lan.test", "algorithm": "hmac-sha256", "records": ["nas"],
                       "record_types": ["TXT"]},
                      {"name": "free", "domain": "lan.test", "algorithm": "hmac-sha512", "records": ["printer"],
                       "record_types": ["TXT"]},
                      {"name": "wide", "domain": "lan.test", "any_name": True, "record_types": ["A", "TXT"]}]}

key, said = edit_tsig_names(DATA, "npm", {"add": ["web"], "drop": [], "add_with_aliases": ["proxy"]})
check("ACME key: a name of the zone added, and a record with its aliases; zone and algorithm kept",
      key["records"] == ["nas", "web"] and key["records_with_aliases"] == ["proxy"] and key["domain"] == "lan.test"
      and key["algorithm"] == "hmac-sha256" and said == ["add web", "add proxy and its aliases"], (key, said))
data2 = copy.deepcopy(DATA)
data2["tsig_keys"][0] = key
key3, said = edit_tsig_names(data2, "npm", {"drop": ["nas", "web"]})
check("names removed one at a time while one entry stays", "records" not in key3
      and key3["records_with_aliases"] == ["proxy"] and said == ["remove nas", "remove web"], (key3, said))
key4, said = edit_tsig_names(data2, "npm", {"drop_with_aliases": ["proxy"]})
check("a record with its aliases removed whole", "records_with_aliases" not in key4 and key4["records"] == ["nas", "web"]
      and said == ["remove proxy and its aliases"], (key4, said))
key5, said = edit_tsig_names(DATA, "free", {"add": ["scanner"]})
check("Custom key: a name typed in (not a record of the zone) added", key5["records"] == ["printer", "scanner"], key5)
key6, said = edit_tsig_names(DATA, "wide", {"scope": "records", "add": ["nas"], "record_types": ["TXT"]})
check("Custom key: scope from any name to records, with a name and its types",
      "any_name" not in key6 and key6["records"] == ["nas"] and key6["record_types"] == ["TXT"]
      and "scope records" in said, (key6, said))
key7, said = edit_tsig_names(DATA, "free", {"scope": "any_name", "record_types": ["A", "AAAA"]})
check("Custom key: scope to any name drops its names", key7.get("any_name") is True and "records" not in key7
      and key7["record_types"] == ["A", "AAAA"], key7)
key8, _ = edit_tsig_names(DATA, "free", {"scope": "primary"})
check("Custom key: scope to the zone's challenge names (primary)", key8.get("primary") is True
      and "records" not in key8, key8)

before = copy.deepcopy(DATA)
for why, name, edit, word in (
        ("a key no longer there", "ghost", {"add": ["web"]}, "no TSIG key named 'ghost'"),
        ("nothing to change", "npm", {}, "nothing to change"),
        ("an unknown field", "npm", {"secret": "x"}, "cannot change secret"),
        ("a name not valid as a record name", "npm", {"add": ["bad name"]}, "not valid as a record name"),
        ("a wildcard", "free", {"add": ["*.apps"]}, "not valid as a record name"),
        ("a name already granted", "npm", {"add": ["nas"]}, "already granted"),
        ("a name not granted removed", "npm", {"drop": ["web"]}, "not granted"),
        ("the key's last name removed", "npm", {"drop": ["nas"]}, "remove the key instead"),
        ("ACME key: a name not of the zone", "npm", {"add": ["printer"]}, "not a record of lan.test"),
        ("ACME key: a scope", "npm", {"scope": "any_name"}, "ACME (DNS-01) key"),
        ("ACME key: record types", "npm", {"record_types": ["A"]}, "ACME (DNS-01) key"),
        ("a CNAME picked with its aliases", "free", {"add_with_aliases": ["web"]}, "not an A or AAAA record"),
        ("aliases already granted", "free", {"add_with_aliases": ["proxy"], "add": []}, None),
        ("an unknown scope", "free", {"scope": "everything"}, "scope must be one of"),
        ("no record type", "free", {"record_types": []}, "at least one record type"),
        ("names with another scope", "free", {"scope": "primary", "add": ["x"]}, "only with the scope records"),
        ("names that are not a list", "npm", {"add": [3]}, "must be a list of names")):
    if word is None:                    # the setup of the next case: proxy granted with aliases to "free"
        k, _ = edit_tsig_names(DATA, "free", edit)
        DATA["tsig_keys"][1] = k
        before = copy.deepcopy(DATA)
        try:
            edit_tsig_names(DATA, "free", edit)
            check("refused: aliases already granted", False)
        except ValidationError as e:
            check("refused: a record with aliases already granted, saying so", "already granted" in str(e), e)
        continue
    try:
        edit_tsig_names(DATA, name, edit)
        check(f"refused: {why}", False, "accepted")
    except ValidationError as e:
        check(f"refused: {why}, saying why, nothing changed", word in str(e) and DATA == before, e)

# ---- 2.1.4.12: a record removed, a record renamed
acme = {"domain": "lan.test", "dns": copy.deepcopy(DATA["dns"]),
        "tsig_keys": [{"name": "npm", "domain": "lan.test", "records": ["nas", "web"], "records_with_aliases": ["proxy"],
                       "record_types": ["TXT"]},
                      {"name": "free", "domain": "lan.test", "records": ["nas", "printer"], "record_types": ["TXT"]}]}
was = copy.deepcopy(acme)
acme["dns"]["dynamic_zone_var"]["A"] = [r for r in acme["dns"]["dynamic_zone_var"]["A"] if r["name"] != "nas"]
out = drop_removed_names(was, acme, "dynamic_zone_var")
check("a record removed: dropped from the ACME key, with a note; the Custom key keeps it",
      out == [("npm", ["nas"])] and acme["tsig_keys"][0]["records"] == ["web"]
      and "nas dropped" in acme["tsig_keys"][0]["notes"][0] and acme["tsig_keys"][1]["records"] == ["nas", "printer"],
      (out, acme["tsig_keys"]))
was = copy.deepcopy(acme)
acme["dns"]["dynamic_zone_var"]["A"] = [r for r in acme["dns"]["dynamic_zone_var"]["A"] if r["name"] != "proxy"]
out = drop_removed_names(was, acme, "dynamic_zone_var")
check("an A record removed: its entry with aliases dropped too", out == [("npm", ["proxy and its aliases"])]
      and "records_with_aliases" not in acme["tsig_keys"][0], (out, acme["tsig_keys"][0]))
was = copy.deepcopy(acme)
acme["dns"]["dynamic_zone_var"]["CNAME"].append({"name": "web", "canonical": "pi-core"})
acme["dns"]["dynamic_zone_var"]["CNAME"].pop(0)        # web -> proxy removed, web -> pi-core still there
check("a name another record still has keeps its grant", drop_removed_names(was, acme, "dynamic_zone_var") == []
      and acme["tsig_keys"][0]["records"] == ["web"], acme["tsig_keys"][0])
check("negative: a removal in a zone no key names changes nothing",
      drop_removed_names(was, {**acme, "dns": {}}, "home.lan") == [])

ren = {"domain": "lan.test", "tsig_keys": [{"name": "host", "domain": "lan.test", "records": ["pi-core", "web"],
                                            "records_with_aliases": ["pi-core"]},
                                           {"name": "other", "domain": "home.lan", "records": ["pi-core"]}]}
check("a rename: the site zone's keys follow it in both lists", rename_tsig_names(ren, "pi-core", "fabric-1") == ["host"]
      and ren["tsig_keys"][0]["records"] == ["fabric-1", "web"]
      and ren["tsig_keys"][0]["records_with_aliases"] == ["fabric-1"], ren)
check("negative: another zone's key and the same name are left alone", ren["tsig_keys"][1]["records"] == ["pi-core"]
      and rename_tsig_names(ren, "web", "web") == [])

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
