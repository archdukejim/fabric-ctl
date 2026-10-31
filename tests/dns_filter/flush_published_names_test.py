#!/usr/bin/env python3
"""The filtering resolver forgets the names fabric just published (decision 2.1.10.46, manual 1.10.4.44): rndc's
flushname for each, flushtree for a zone flushed whole; nothing asked with the resolver off; a failure said, never
raised. The resolver's rndc stood in for (the real resolver: tests/zones/run.py).

    python3 tests/dns_filter/flush_published_names_test.py
"""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.dns_filter.flush_published_names import flush_published_names  # noqa: E402

FAILED = 0
ON = {"install_resolver": True}


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def rndc(fail_on=None, down=False):
    asked = []

    def call(args, timeout=30):
        asked.append(list(args))
        if down:
            return None
        bad = fail_on and args[1] == fail_on
        return subprocess.CompletedProcess(args, 1 if bad else 0, "", "rndc: 'flushname' failed: not found" if bad
                                           else "")
    return call, asked


call, asked = rndc()
out = flush_published_names(ON, {"names": ["kubres.lan.test.", "50.10.88.10.in-addr.arpa."], "trees": ["home.lan"]},
                            call=call)
check("each changed name flushed (every view: no view named), a new zone's whole tree first",
      asked == [["flushtree", "home.lan"], ["flushname", "kubres.lan.test"], ["flushname", "50.10.88.10.in-addr.arpa"]]
      and out == {"flushed": 3, "error": None}, (asked, out))
call, asked = rndc()
out = flush_published_names({"install_resolver": False}, {"names": ["kubres.lan.test."], "trees": []}, call=call)
check("the filtering resolver off: nothing asked", asked == [] and out == {"flushed": 0, "error": None}, out)
call, asked = rndc()
out = flush_published_names(ON, {"names": [], "trees": []}, call=call)
check("nothing changed: nothing asked", asked == [] and out == {"flushed": 0, "error": None}, out)
call, asked = rndc(fail_on="b.lan.test")
out = flush_published_names(ON, {"names": ["a.lan.test.", "b.lan.test.", "c.lan.test."], "trees": []}, call=call)
check("a flush the resolver refuses: said, naming the name and rndc's reason; the rest not asked; not raised",
      out["flushed"] == 1 and "b.lan.test" in out["error"] and "not found" in out["error"]
      and asked[-1] == ["flushname", "b.lan.test"] and len(asked) == 2, (out, asked))
call, asked = rndc(down=True)
out = flush_published_names(ON, {"names": ["a.lan.test."], "trees": []}, call=call)
check("the resolver not answering: said, with how to look", out["flushed"] == 0
      and "is bind9-resolver running" in out["error"], out)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
