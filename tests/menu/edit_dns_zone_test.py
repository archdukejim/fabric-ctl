#!/usr/bin/env python3
"""The setup menu's zone editor and split DNS by zone (menu/edit_dns_zone, decision 2.1.4.18, manual 1.4.1.13): a new
record is asked no networks (it is the All networks tab's, answering every network of the zone); a zone mapped to
some networks or split says so, and that its networks and splits are changed in the console; a zone answering every
network with no split says nothing. The terminal stood in for. Pure; no container.

    python3 tests/menu/edit_dns_zone_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.menu.edit_dns_zone as edz  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


asked = []


def ask(qid, prompt, default=None):
    asked.append(qid)
    return {"menu.dns.record.name": "web", "menu.dns.record.ip": "10.1.20.5"}.get(qid, default or "")


edz.ask = ask
form = edz._prompt_record("A")
check("a new record: its fields alone, no networks asked (the All networks tab's)",
      form == {"name": "web", "ip": "10.1.20.5"} and asked == ["menu.dns.record.name", "menu.dns.record.ip"], asked)
check("a zone answering every network with no split: no note", edz._networks_note({"A": []}) == "")
note = edz._networks_note({"networks": ["10.1.20.0/24"], "splits": [{"subnets": ["10.1.20.0/24"]}]})
check("a mapped and split zone: said, with the console named for its networks and splits",
      "answers 10.1.20.0/24 only and has 1 split" in note and "changed in the console" in note, note)
note = edz._networks_note({"splits": [{"subnets": ["10.1.20.0/24"]}, {"subnets": ["10.1.21.0/24"]}]})
check("...a zone with two splits: counted", "has 2 splits" in note and "All networks tab" in note, note)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
