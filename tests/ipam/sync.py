#!/usr/bin/env python3
"""The `ipam` suite, Sync now with no container (manual 1.10.4.28, decision 2.1.10.29): Sync now refused while an apply
holds the settings' lock, at a site without Kea and before the upgrade, changing nothing; the poll forced under the
lock it already holds; BIND's records published only when DNS waits; a failed publish said with what was done,
audited, the lock released; `fabricctl ipam sync`. The quick path against a real BIND: tests/zones/run.py. The
agent's route and the Networks tab's card come with areas 7 and 9 of the port (1.10.4.41).

    python3 tests/ipam/sync.py
"""
import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_cmd  # noqa: E402
import fabriclib.ipam.sync.sync_plan as m_sync  # noqa: E402
m_cmd.apply_intent = __import__("functools").partial(  # the apply intent in a folder of the test's own
    __import__("fabriclib.common.apply_intent", fromlist=["x"]).apply_intent,
    __import__("os").path.join(__import__("tempfile").mkdtemp(), ".apply.intent"))

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def refused(fn, words):
    try:
        fn()
    except ValidationError as e:
        return words in str(e) or str(e)
    return "not refused"


V = {"site_name": "home", "install_kea": True}


# ---- Sync now
class Lock:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


CALLS, AUDIT = [], []
m_sync.write_audit = lambda actor, event, detail, source="cli", path=None: AUDIT.append((actor, event, detail, source))


def poller(pending, state="same plan", restarted=False):
    def poll(v, container="samba", secrets=None, force=False, take_lock=None):
        held = take_lock()
        CALLS.append(("poll", force, held is not None))
        held.close()
        return {"state": state, "kea_restarted": restarted, "firewall": False, "dns_pending": pending, "usn": 9}
    return poll


def publisher(fail=False):
    def publish(secrets):
        CALLS.append(("publish", secrets))
        if fail:
            raise ValidationError("BIND did not take the new zone list: BIND did not answer (is bind9 running?)")
        return {"zones": ["lan.test", "20.1.10.in-addr.arpa"], "new": ["20.1.10.in-addr.arpa"], "config": True,
                "resolver": False}
    return publish


def sync(v=V, pending=False, lock=None, settings=None, fail=False, **kw):
    lk = lock if lock is not None else Lock()
    out = m_sync.sync_plan(v, "alice", source="web", secrets={"s": 1}, poll=poller(pending, **kw),
                           publish=publisher(fail), take_lock=lambda: lk if lock is not False else None,
                           settings=settings or (lambda: {"dhcp": {"interfaces": ["eth0"]}}))
    return out, lk


# covers: cli:ipam.sync -
before = (len(CALLS), len(AUDIT))
check("refused: an apply holds the settings' lock, saying so; nothing polled, nothing audited",
      refused(lambda: sync(lock=False), "an apply is running") is True and (len(CALLS), len(AUDIT)) == before)
check("refused: a site without Kea", refused(lambda: sync({"site_name": "home"}), "DHCP is off at this site") is True)
check("refused: the subnets still in the settings (not upgraded): an apply serves them", refused(
    lambda: sync(settings=lambda: {"dhcp": {"subnets": []}}), "still in its settings") is True
    and (len(CALLS), len(AUDIT)) == before)
# covers: cli:ipam.sync +
out, lk = sync(pending=False)
check("DNS current: the poll forced under the lock Sync now holds, nothing published, the lock released, audited",
      CALLS[-1] == ("poll", True, True) and out["dns"] is None and lk.closed
      and AUDIT[-1][1] == "IPAM_SYNC" and "dns=current" in AUDIT[-1][2] and AUDIT[-1][3] == "web", (CALLS, AUDIT))
out, lk = sync(pending=True, state="rendered", restarted=True)
check("DNS pending: the poll, then BIND's records by the quick path with the same secrets; what was published said",
      CALLS[-2:] == [("poll", True, True), ("publish", {"s": 1})] and out["kea_restarted"] is True
      and out["dns"]["zones"] == ["lan.test", "20.1.10.in-addr.arpa"] and lk.closed
      and "zones=lan.test,20.1.10.in-addr.arpa" in AUDIT[-1][2], (out, AUDIT[-1]))
n = len(AUDIT)
lk = Lock()
why = refused(lambda: sync(pending=True, lock=lk, fail=True, restarted=True), "Kea is in line with the plan")
check("BIND refusing: said with what was done (Kea in line, BIND's records not), audited as failed, lock released",
      why is True and len(AUDIT) == n + 1 and "dns=failed" in AUDIT[-1][2] and lk.closed, (why, AUDIT[-1:]))


def poll_fails(v, container="samba", secrets=None, force=False, take_lock=None):
    raise ValidationError("the domain cannot be asked: the DC did not answer")


lk = Lock()
n = len(AUDIT)
check("the poll failing (the DC): its refusal, the lock released, nothing audited", refused(
    lambda: m_sync.sync_plan(V, "alice", secrets={}, poll=poll_fails, publish=publisher(), take_lock=lambda: lk,
                             settings=lambda: {}), "the DC did not answer") is True and lk.closed and len(AUDIT) == n)


# ---- `fabricctl ipam sync`
def cli(*argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e):
        code = m_cmd.run_ipam_command(V, list(argv))
    return code, o.getvalue(), e.getvalue()


m_cmd.sync_plan = lambda v, actor, container="samba", secrets=None: {
    "state": "rendered", "kea_restarted": True, "firewall": True, "dns_pending": True,
    "dns": {"zones": ["lan.test"], "new": [], "config": False, "resolver": False}}
code, o, e = cli("sync")
check("fabricctl ipam sync: what the poll did and the zones published (exit 0)", code == 0
      and "Kea updated" in o and "firewall brought in line" in o and "DNS: published: lan.test" in o, (o, e))


def busy(v, actor, container="samba", secrets=None):
    raise ValidationError("an apply is running (it holds the settings' lock) and reads the plan itself")


m_cmd.sync_plan = busy
code, o, e = cli("sync")
check("fabricctl ipam sync during an apply: refused, saying why (exit 1)", code == 1 and "an apply is running" in e,
      (code, e))
code, o, e = cli("sync", "--site", "lab")
check("fabricctl ipam sync --site: refused (a sync is this site's own)", code == 1 and "this site's own" in e, e)
code, o, e = cli("sync", "now")
check("fabricctl ipam sync with an argument: the usage (exit 2)", code == 2 and "fabricctl ipam sync" in e, code)


print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
