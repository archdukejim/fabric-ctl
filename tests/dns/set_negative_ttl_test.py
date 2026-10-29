#!/usr/bin/env python3
"""A zone fabric does not render again (the DHCP subzone) given the negative-caching TTL of 2.1.4.9 the way an
administrator edits a dynamic zone: freeze, edit the SOA's minimum and serial, thaw. Real files in fabric's one-line
form and as BIND writes them; rndc stood in for (the kea suite asks a real BIND).

    python3 tests/dns/set_negative_ttl_test.py
"""
import os
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.dns.set_negative_ttl import set_negative_ttl  # noqa: E402

FAILED = 0
ONE_LINE = ("$TTL 3600\n$ORIGIN dhcp.lan.test.\n@  IN SOA ns.lan.test. hostmaster.lan.test. (2761000000 3600 1800 604800 "
            "300)\n@  IN NS  ns.lan.test.\n")
BIND_FORM = ("$ORIGIN .\n$TTL 3600\t; 1 hour\ndhcp.lan.test\t\tIN SOA\tns.lan.test. hostmaster.lan.test. (\n"
             "\t\t\t\t2761000007 ; serial\n\t\t\t\t3600       ; refresh (1 hour)\n\t\t\t\t1800       ; retry (30 minutes)\n"
             "\t\t\t\t604800     ; expire (1 week)\n\t\t\t\t300        ; minimum (5 minutes)\n\t\t\t\t)\n"
             "\t\t\tNS\tns.lan.test.\n$ORIGIN dhcp.lan.test.\nlaptop1\t\t\tA\t10.0.0.11\n")


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


class Rndc:
    def __init__(self, freeze=0, thaw=0):
        self.asked, self.codes = [], {"freeze": freeze, "thaw": thaw}

    def __call__(self, args, timeout=15):
        self.asked.append(args[0])
        code = self.codes[args[0]]
        return None if code is None else subprocess.CompletedProcess(args, code, "", "rndc: refused" if code else "")


def zone(tmp, text, journal=False):
    path = os.path.join(tmp, "db.dhcp.lan.test")
    with open(path, "w") as f:
        f.write(text)
    if journal:                                  # a journal newer than the file: changes the file does not hold
        past = time.time() - 60
        os.utime(path, (past, past))
        open(path + ".jnl", "w").close()
    return path


with tempfile.TemporaryDirectory() as tmp:
    path = zone(tmp, BIND_FORM)
    r = Rndc()
    out = set_negative_ttl("dhcp.lan.test", path, 30, call=r)
    text = open(path).read()
    check("BIND's own form: frozen, the minimum set to 30 and the serial raised, thawed; the records and comments kept",
          out == "set" and r.asked == ["freeze", "thaw"] and "\t\t\t\t30        ; minimum" in text
          and "2761000007 ; serial" not in text and "laptop1\t\t\tA\t10.0.0.11" in text, (out, r.asked, text))
    r = Rndc()
    check("a zone that has 30 s already: nothing asked, nothing written",
          set_negative_ttl("dhcp.lan.test", path, 30, call=r) == "already" and r.asked == [] and open(path).read()
          == text, r.asked)

with tempfile.TemporaryDirectory() as tmp:
    path = zone(tmp, ONE_LINE)
    out = set_negative_ttl("dhcp.lan.test", path, 30, call=Rndc(freeze=None))
    text = open(path).read()
    check("fabric's one-line form with BIND not running and no journal: the file alone is changed (BIND reads it on "
          "start)", out == "set" and "604800 30)" in text and "(2761000000 " not in text, (out, text))

with tempfile.TemporaryDirectory() as tmp:
    path = zone(tmp, ONE_LINE, journal=True)
    out = set_negative_ttl("dhcp.lan.test", path, 30, call=Rndc(freeze=None))
    check("BIND not running with a journal newer than the file: left, the file unchanged (the journal would no longer "
          "match it), and said why", out.startswith("left: BIND is not running") and open(path).read() == ONE_LINE, out)

with tempfile.TemporaryDirectory() as tmp:
    path = zone(tmp, ONE_LINE)
    out = set_negative_ttl("dhcp.lan.test", path, 30, call=Rndc(thaw=1))
    check("BIND refusing the thaw: said, with what it said, and that the next apply tries again",
          out.startswith("left: BIND did not take the file back (rndc: refused)") and "next apply" in out, out)

with tempfile.TemporaryDirectory() as tmp:
    path = zone(tmp, "$TTL 3600\n@ IN NS ns.lan.test.\n")
    r = Rndc()
    out = set_negative_ttl("dhcp.lan.test", path, 30, call=r)
    check("a file whose SOA cannot be read: left, nothing asked or written", out.startswith("left: its SOA")
          and r.asked == [] and open(path).read() == "$TTL 3600\n@ IN NS ns.lan.test.\n", out)

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
