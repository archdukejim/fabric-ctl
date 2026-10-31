"""A held change done with a warning says it on its row of the Review (2.1.4.9: a zone published while the filtering
resolver did not forget its cached answers), and DNS' Apply says the same of its flush; a change done without one
leaves its row empty. Pure: the routes and apply_dns stood in for (the zones suite runs the real ones).
    python3 tests/agent/pending_store_test.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from agent.pending_store import PendingStore  # noqa: E402
import agent.post_pending as pp  # noqa: E402
import fabriclib.dns.apply_dns as apply_dns_module  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


def applied(result):
    """One zone added through the queue, its route answering result; returns the Review's rows."""
    store = PendingStore(run=lambda route, actor, body, perms, session: result, state=lambda route, body: {},
                         need=lambda route: "dns:write", start_job=lambda kind, owner, fn: fn() and {"id": "j"})
    store.hold("alice", {"dns:write"}, "zones", ["zones"], {"name": "home.lan"}, "Add zone home.lan")
    store.apply("alice", {"dns:write"}, "zones", "alice", "sid")
    return store.page("alice", "zones", lambda page: True)["queue"][0]["items"]


rows = applied({"key": "home.lan", "warning": "the filtering resolver did not forget home.lan (x)"})
check("a change done with a warning: done, its row says the warning",
      rows[0]["state"] == "done" and rows[0]["why"] == "the filtering resolver did not forget home.lan (x)", rows)
rows = applied({"key": "home.lan"})
check("a change done without one: done, its row empty", rows[0]["state"] == "done" and rows[0]["why"] == "", rows)


def publish_note(answer):
    real = apply_dns_module.apply_dns
    apply_dns_module.apply_dns = lambda actor, source="web": answer
    try:
        return pp._finish_dns([["zones", "lan.test", "records"]])[1]("alice")
    finally:
        apply_dns_module.apply_dns = real


said = publish_note({"landing_cert": None, "flushed": 0,
                     "flush_error": "the filtering resolver did not forget www.lan.test (x)"})
check("DNS' Apply whose flush failed: its last row says the warning (the records are published)",
      said == "warning: the filtering resolver did not forget www.lan.test (x)", said)
said = publish_note({"landing_cert": {"missing": ["new.lan.test"], "extra": []}, "flushed": 1, "flush_error": None})
check("DNS' Apply whose flush worked: only what else waits (the landing certificate), no warning",
      "landing page's certificate lacks new.lan.test" in said and "warning" not in said, said)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
