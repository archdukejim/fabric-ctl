#!/usr/bin/env python3
"""The `ipam` suite, Sync now with no container (manual 1.10.4.28, decision 2.1.10.29): what the poll last reported
(sync_status); Sync now refused while an apply holds the settings' lock, at a site without Kea and before the upgrade,
changing nothing; the poll forced under the lock it already holds; BIND's records published only when DNS waits; a
failed publish said with what was done, audited, the lock released; `fabricctl ipam sync`; the agent's route and its
permission; the Networks tab's card and its form. The quick path against a real BIND: tests/zones/run.py.

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
from fabriclib.ipam.sync.sync_status import sync_status  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

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


# ---- what the poll last reported
V = {"site_name": "home", "install_kea": True}
STATES = {}
check("no Kea here: nothing to show", sync_status({"site_name": "home"}, load=lambda n: {})["kea"] is False)
check("the poll never ran: not polled, nothing pending", sync_status(V, load=lambda n: STATES.get(n, {})) == {
    "kea": True, "polled": False, "usn": None, "rendered": "", "dns_pending": False})
STATES.update({"plan-watch": {"usn": 7, "dns": "new", "rendered": "2026-10-13 09:30:00"}, "plan-dns": {"dns": "old"}})
st = sync_status(V, load=lambda n: STATES.get(n, {}))
check("the plan's names differ from what BIND took: DNS pending, with when Kea was last rendered",
      st["dns_pending"] is True and st["rendered"] == "2026-10-13 09:30:00" and st["usn"] == 7, st)
STATES["plan-dns"] = {"dns": "new"}
check("BIND took them: not pending", sync_status(V, load=lambda n: STATES.get(n, {}))["dns_pending"] is False)


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


# covers: cli:ipam.sync agent:post.ipam.sync -
before = (len(CALLS), len(AUDIT))
check("refused: an apply holds the settings' lock, saying so; nothing polled, nothing audited",
      refused(lambda: sync(lock=False), "an apply is running") is True and (len(CALLS), len(AUDIT)) == before)
check("refused: a site without Kea", refused(lambda: sync({"site_name": "home"}), "DHCP is off at this site") is True)
check("refused: the subnets still in the settings (not upgraded): an apply serves them", refused(
    lambda: sync(settings=lambda: {"dhcp": {"subnets": []}}), "still in its settings") is True
    and (len(CALLS), len(AUDIT)) == before)
# covers: cli:ipam.sync agent:post.ipam.sync +
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
      and "Kea restarted" in o and "firewall brought in line" in o and "DNS: published: lan.test" in o, (o, e))


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

# ---- the agent
check("permission: Sync now needs dhcp:write; the auditor has it not, a network operator has it",
      required_permission("POST", ["ipam", "sync"]) == "dhcp:write"
      and "dhcp:write" not in BUNDLES["fabric-auditor"] and "dhcp:write" in BUNDLES["fabric-network-operator"]
      and required_permission("GET", ["ipam", "sync"]) is None)
try:
    import agent.post_ipam_sync as m_agent  # noqa: E402
    from agent.route_not_found import RouteNotFound  # noqa: E402
    agent_ok = True
except ImportError as exc:          # the agent's imports need the host's modules (yaml, ...)
    agent_ok, why = False, exc
if agent_ok:
    m_agent.load_vars = lambda: V
    SEEN = []
    m_agent.sync_plan = lambda v, actor, source="cli": SEEN.append((actor, source)) or {"state": "same plan"}
    m_agent.post_ipam_sync(["ipam", "sync"], "alice", {})
    check("POST /v1/ipam/sync: Sync now as the signed-in user, from the web", SEEN == [("alice", "web")], SEEN)
    try:
        m_agent.post_ipam_sync(["ipam", "sync", "dns"], "alice", {})
        nf = False
    except RouteNotFound:
        nf = True
    check("another route under ipam/sync: not found (404)", nf)
else:
    check("the agent's sync route imports", False, why)

# ---- the console: the card and the button
sys.path.insert(0, REPO)
try:
    from webui import agentclient as actions  # noqa: E402
    from webui import views  # noqa: E402
    import webui.routes.networks_sync_post as m_post  # noqa: E402
    web_ok = True
except ImportError as exc:          # jinja2 missing on this machine
    web_ok, why = False, exc


class H:
    def __init__(self):
        self.to = None

    def redirect(self, url, headers=None):
        self.to = url


if web_ok:
    OV = {"site": "home", "own": "home", "sites": [], "vlans": [], "networks": [], "leases_shown": True, "stale": "",
          "leases_error": "", "block": 1, "suggested_block": 1, "error": "", "local_scan": None,
          "sync": {"kea": True, "polled": True, "usn": 7, "rendered": "2026-10-13 09:30:00", "dns_pending": True}}
    CTX = {"user": "alice", "csrf": "tok", "perms": ["dhcp:read", "dhcp:write"], "version": "0.8.0"}
    page = views.networks(CTX, OV)
    # covers: web:post.networks.sync +
    check("the Networks tab's Sync now card: when Kea was last rendered, DNS pending, the button",
          "Sync now" in page and "2026-10-13 09:30:00" in page and "DNS waits for an apply or Sync now" in page
          and 'action="/networks/sync"' in page, page[:2500])
    page = views.networks(CTX, {**OV, "sync": {**OV["sync"], "dns_pending": False}})
    check("DNS in line: said so", "DNS in line with the plan" in page)
    # covers: web:post.networks.sync -
    page = views.networks({**CTX, "perms": ["dhcp:read"]}, OV)
    check("without dhcp:write: the state shown, no button, the permission named",
          'action="/networks/sync"' not in page and "dhcp:write" in page and "DNS waits" in page)
    page = views.networks(CTX, {**OV, "site": "lab", "sync": None})
    check("another site's view: no Sync now card (a sync is this site's)", 'action="/networks/sync"' not in page)
    actions.sync_now = lambda: {"state": "rendered", "kea_restarted": True, "firewall": False, "dns_pending": True,
                                "dns": {"zones": ["lan.test"]}}
    h = H()
    m_post.networks_sync_post(h, {"csrf": "tok"})
    check("the button: back to the tab with what it did", h.to.startswith("/networks?msg=Synced")
          and "Kea+restarted" in h.to and "lan.test" in h.to, h.to)

    def no():
        raise actions.ValidationError("an apply is running (it holds the settings' lock)")
    actions.sync_now = no
    h = H()
    m_post.networks_sync_post(h, {})
    check("refused by the agent: back to the tab saying why", h.to.startswith("/networks?err=Sync+now")
          and "apply+is+running" in h.to, h.to)
else:
    print(f"SKIP the console's Sync now: {why}")

print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
