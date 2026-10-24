#!/usr/bin/env python3
"""The names an apply or Sync now is about to change (decision 2.1.10.46, manual 1.10.4.44): each changed zone's
rendered file against the deployed one, name by name; a new zone, or one with many changes, flushed whole. Real
zone files, as fabric renders them and BIND writes them; no container.

    python3 tests/dns/changed_names_test.py
"""
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.dns.changed_names import MAX_NAMES, changed_names  # noqa: E402

FAILED = 0
HEAD = ("$TTL 3600\n$ORIGIN lan.test.\n@ IN SOA ns.lan.test. admin.lan.test. ( {serial} 3600 600 86400 300 )\n"
        "@ IN NS ns.lan.test.\nns IN A 10.0.0.2\n")


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def zone(tmp, name, serial, body):
    path = os.path.join(tmp, name)
    with open(path, "w") as f:
        f.write(HEAD.format(serial=serial) + body)
    return path


with tempfile.TemporaryDirectory() as tmp:
    old = zone(tmp, "old", 1, "www IN A 10.0.0.5\nnas IN A 10.0.0.9\nmail IN MX 10 nas\nold IN A 10.0.0.7\n")
    new = zone(tmp, "new", 2, "www IN A 10.0.0.5\nnas IN A 10.0.0.19\nmail IN MX 10 nas\nkubres IN A 10.0.0.50\n")
    out = changed_names([("lan.test", new, old)])
    check("a name added, a name changed and a name removed are each named; the unchanged ones and the SOA's new "
          "serial are not", out == {"names": ["kubres.lan.test.", "nas.lan.test.", "old.lan.test."], "trees": []},
          out)
    same = zone(tmp, "same", 3, "www IN A 10.0.0.5\nnas IN A 10.0.0.9\nmail IN MX 10 nas\nold IN A 10.0.0.7\n")
    out = changed_names([("lan.test", same, old)])
    check("only the serial moved: no name to flush", out == {"names": [], "trees": []}, out)
    out = changed_names([("home.lan", new, os.path.join(tmp, "not-deployed"))])
    check("a new zone (no deployed file yet): flushed whole", out == {"names": [], "trees": ["home.lan"]}, out)
    many = zone(tmp, "many", 4, "".join(f"h{i} IN A 10.0.1.{i}\n" for i in range(MAX_NAMES + 1)))
    out = changed_names([("lan.test", many, old)])
    check(f"more than {MAX_NAMES} names changed in a zone: the zone flushed whole instead",
          out == {"names": [], "trees": ["lan.test"]}, out)
    out = changed_names([])
    check("nothing changed: nothing to flush", out == {"names": [], "trees": []}, out)
    try:
        changed_names([("lan.test", os.path.join(tmp, "missing"), old)])
        check("a rendered file that cannot be read: refused loudly", False)
    except OSError:
        check("a rendered file that cannot be read: refused loudly (OSError)", True)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
