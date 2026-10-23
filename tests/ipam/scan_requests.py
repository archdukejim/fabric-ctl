#!/usr/bin/env python3
"""The `ipam` suite, scans at another site with no container (manual 1.10.4.36, decision 2.1.10.38): a request asked
only by a caller holding `networks:scan` at the serving site (root acting for the Enterprise Admin), for a subnet of
that site's plan, at most a /22, never this site's own, one pending per subnet and MAX_PENDING per site, written
naming the person and audited; refused, nothing written. At the serving site the plan poll answers: a request older
than a day removed; one not made by a fabric DC's agent account, or naming a person this site's grants do not let
scan here, refused (audited, never run); root at a fabric host always allowed; one pending past the hour expired;
PER_RUN run, the result written back; a scan busy for now kept pending; another refusal answered with why. The poll
runs them when the USN moves and while one is pending, and fails loudly after Kea's part when they cannot be
answered. `fabricctl ipam scan <subnet> --site S` and `scan-requests`. The DC's own operations against a real
directory: tests/samba/ipam.py. The agent's route comes with area 7 of the port (1.10.4.41).

    python3 tests/ipam/scan_requests.py
"""
import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.ipam.common.scan_busy import ScanBusy  # noqa: E402
import fabriclib.ipam.poll_plan as m_poll  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_cmd  # noqa: E402
import fabriclib.ipam.scancontrol.list_scan_requests as m_list  # noqa: E402
import fabriclib.ipam.scancontrol.request_scan as m_req  # noqa: E402
import fabriclib.ipam.scancontrol.run_scan_command as m_rsc  # noqa: E402
import fabriclib.ipam.scancontrol.run_scan_requests as m_run  # noqa: E402
from fabriclib.ipam.scancontrol.limits import KEEP, MAX_PENDING, RESULT_LIMIT, RUN_WITHIN  # noqa: E402

FAILED = 0
NOW = 1_800_000_000.0


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


AUDIT, WRITES, CHECKED = [], [], []
m_req.write_audit = m_run.write_audit = lambda actor, action, detail, source="cli", path=None: AUDIT.append(
    (actor, action, detail, source))
V = {"site_name": "home", "dc_name": "dc1", "install_kea": True}
SEC = {"ad_agent_password": "x"}
BRANCH = {"sites": [{"name": "home", "block": 1}, {"name": "branch", "block": 2}],
          "plans": {"branch": {"vlans": [], "subnets": [
              {"name": "cams", "cidr": "10.2.20.0/24"}, {"name": "wide", "cidr": "10.2.32.0/21"}]}}}
PENDING = []


def read(v, secrets, of, container):
    return BRANCH


def requests(v, site, secrets, container):
    return list(PENDING)


def write(v, secrets, do, site, subnet, rid, fields=None, container="samba"):
    WRITES.append((do, site, subnet, rid, fields))
    return "ok"


def allow(v, caller, action, target=None, container="samba"):
    CHECKED.append((caller, action, target))
    return {"tier": "enterprise" if caller is None else "delegated", "by": "tier" if caller is None else "grant ops"}


def deny(v, caller, action, target=None, container="samba"):
    CHECKED.append((caller, action, target))
    raise ValidationError(f"no grant gives you networks scan at {target['site']} (manual 1.6.13.12)")


def ask(site, subnet, caller=None, check=allow):
    return m_req.request_scan(V, caller or "root", site, subnet, SEC, "samba", caller=caller, check=check, read=read,
                              requests=requests, write=write, now=lambda: NOW)


# ---- asking: request_scan
print("--- a scan asked of another site (request_scan)")
# covers: cli:ipam.scan +
got = ask("branch", "cams")
check("root asks: checked as root (the Enterprise Admin) at the serving site, written naming root@<dc>, pending",
      CHECKED[-1] == (None, "networks:scan", {"site": "branch"}) and WRITES[-1][:3] == ("add", "branch", "cams")
      and WRITES[-1][4] == {"cidr": "10.2.20.0/24", "actor": "root@dc1"} and got["state"] == "pending"
      and got["actor"] == "root@dc1" and got["requested_by"] == "home" and got["id"] == WRITES[-1][3], (got, WRITES))
check("audited: from this DC, the site, the subnet, the request and what allowed it",
      AUDIT[-1][:2] == ("root", "IPAM_SCAN_REQUEST") and "from=dc1 site=branch subnet=10.2.20.0/24" in AUDIT[-1][2]
      and f"request={got['id']}" in AUDIT[-1][2] and "by=tier" in AUDIT[-1][2], AUDIT[-1:])
alice = ask("branch", "10.2.20.0/24", caller="alice")
check("a signed-in person: checked as themself, the request names them; by exact network too",
      CHECKED[-1][0] == "alice" and WRITES[-1][4]["actor"] == "alice" and alice["subnet"] == "cams"
      and "by=grant ops" in AUDIT[-1][2], (CHECKED[-1], WRITES[-1]))
PENDING[:] = [{"id": "old", "cidr": "10.2.20.0/24", "state": "pending", "created_at": NOW - RUN_WITHIN - 5}]
check("a pending request past the hour does not hold the subnet (the poll answers it expired)",
      ask("branch", "cams")["state"] == "pending")
# covers: cli:ipam.scan -
n = len(WRITES), len(AUDIT)
for typed_site, typed, words, who in (
        ("", "cams", "name the site to scan at", None), ("home", "cams", "runs here: fabricctl ipam scan", None),
        ("HOME", "cams", "runs here", None), ("branch", "nosuch", "is not a subnet of branch's plan (cams", None),
        ("branch", "", "name the subnet to scan at branch", None), ("branch", "10.2.20.5/24", "host bits zero", None),
        ("branch", "10.9.9.0/24", "is not a subnet of branch's plan", None),
        ("branch", "wide", "larger than a /22", None)):
    check(f"refused: a request for {typed!r} at {typed_site!r}, saying why",
          refused(lambda: ask(typed_site, typed, who), words) is True,
          refused(lambda: ask(typed_site, typed, who), words))
check("refused: a person without networks:scan at the serving site, saying why, before the plan is read",
      refused(lambda: ask("branch", "cams", "bob", deny), "no grant gives you networks scan at branch") is True)
PENDING[:] = [{"id": "p1", "cidr": "10.2.20.0/24", "state": "pending", "created_at": NOW - 10}]
check("refused: a request for that subnet still pending, pointing at its answer",
      refused(lambda: ask("branch", "cams"), "already pending: its answer shows with fabricctl ipam scan-requests "
                                             "--site branch") is True)
PENDING[:] = [{"id": f"p{i}", "cidr": f"10.2.{i}.0/24", "state": "pending", "created_at": NOW - 10}
              for i in range(MAX_PENDING)]
check(f"refused: {MAX_PENDING} already pending at the serving site",
      refused(lambda: ask("branch", "cams"), f"{MAX_PENDING} scans are already pending at branch") is True)
check("a refused request writes nothing and audits nothing", (len(WRITES), len(AUDIT)) == n, (WRITES[n[0]:], AUDIT))
PENDING[:] = []

# ---- answering: run_scan_requests at the serving site
print("--- the serving site answers (run_scan_requests)")
VB = {"site_name": "branch", "dc_name": "dc2", "install_kea": True}
SCANS = []
RESULT = {"subnet": {"name": "cams", "cidr": "10.2.20.0/24"}, "scanned": 254, "unrecorded": 1, "at": "2026-10-23T10:00",
          "answering": [{"ip": "10.2.20.5", "mac": "aa:bb:cc:00:00:05", "how": "ping+arp", "status": "unrecorded",
                         "kind": "", "name": "", "note": ""}], "allowed": {"by": "a request from home"}}


def row(rid, actor="root@dc1", age=10, state="pending", by_agent=True, cidr="10.2.20.0/24"):
    return {"id": rid, "site": "branch", "subnet": "cams", "cidr": cidr, "requested_by": "home", "actor": actor,
            "state": state, "result": None, "done_at": "", "created": "2026-10-23 10:00", "created_at": NOW - age,
            "owner": "CN=fabric-agent-dc1" if by_agent else "CN=mallory", "by_agent": by_agent}


def scan(v, actor, cidr, source="cli", requested=None):
    SCANS.append((actor, cidr, source, requested))
    return RESULT


def answer(rows, scanner=scan, check=allow):
    WRITES.clear()
    CHECKED.clear()
    return m_run.run_scan_requests(VB, SEC, "samba", requests=lambda v, s, sec, c: list(rows), write=write,
                                   scan=scanner, check=check, now=lambda: NOW)


def answered(rid):
    return next((w for w in WRITES if w[0] == "finish" and w[3] == rid), None)


out = answer([row("r1")])
w = answered("r1")
check("a pending request from a fabric DC, naming root at a fabric host: run here as <person>@<site>, from a request",
      out["ran"] == ["r1"] and SCANS[-1] == ("root@dc1@home", "10.2.20.0/24", "request", {"id": "r1", "by": "home"})
      and not CHECKED, (out, SCANS[-1:], CHECKED))
check("its result written back on it, done, bounded (JSON of the rows)", w and w[4]["state"] == "done"
      and json.loads(w[4]["result"])["rows"][0]["ip"] == "10.2.20.5" and len(w[4]["result"]) <= RESULT_LIMIT, w)
out = answer([row("r2", actor="alice")])
check("a person: checked by this site's own reading of the grants (networks:scan here), then run",
      CHECKED == [("alice", "networks:scan", {"site": "branch"})] and out["ran"] == ["r2"], (CHECKED, out))
n = len(SCANS)
AUDIT.clear()
out = answer([row("r3", actor="bob")], check=deny)
check("refused: a person this site's grants do not let scan here, with why, audited, never run",
      out["refused"] == ["r3"] and answered("r3")[4]["state"] == "refused"
      and "no grant gives you networks scan at branch" in answered("r3")[4]["result"] and len(SCANS) == n
      and AUDIT[-1][1] == "IPAM_SCAN_REQUEST_REFUSED" and "request=r3" in AUDIT[-1][2], (out, WRITES, AUDIT))
out = answer([row("r4", by_agent=False)])
check("refused: a request not made by a fabric DC's agent account (naming who made it), never run",
      out["refused"] == ["r4"] and "not made by a fabric DC's agent account (made by CN=mallory)"
      in answered("r4")[4]["result"] and len(SCANS) == n and not CHECKED, (out, WRITES))
out = answer([row("r5", actor="eve@lab"), row("r6", actor="")])
check("refused: a person this site cannot check (another form, none)", out["refused"] == ["r5", "r6"]
      and "names no person this site can check (eve@lab)" in answered("r5")[4]["result"]
      and "(none)" in answered("r6")[4]["result"] and len(SCANS) == n, (out, WRITES))
out = answer([row("r7", age=RUN_WITHIN + 5)])
check("expired: pending longer than an hour, answered, never run", out["expired"] == ["r7"]
      and answered("r7")[4]["state"] == "expired" and "within an hour" in answered("r7")[4]["result"]
      and len(SCANS) == n, (out, WRITES))
out = answer([row("r8", age=KEEP + 5, state="done"), row("r9", state="done"), row("r10", state="refused")])
check("removed: a request older than a day, in any state; one already answered is left as it is",
      out["removed"] == ["r8"] and WRITES == [("remove", "branch", "cams", "r8", None)] and not out["ran"]
      and len(SCANS) == n, (out, WRITES))
out = answer([row("r11"), row("r12", cidr="10.2.21.0/24")])
check("one scan per run (PER_RUN): the next stays pending, and the poll is told to read them again",
      out["ran"] == ["r11"] and out["pending"] is True and answered("r12") is None, (out, WRITES))


def busy(v, actor, cidr, source="cli", requested=None):
    raise ScanBusy("another scan is running: try again when it ends")


out = answer([row("r13")], scanner=busy)
check("a scan refused only for now (busy, too soon): kept pending, not answered", out["pending"] is True
      and not out["refused"] and answered("r13") is None, (out, WRITES))


def nokea(v, actor, cidr, source="cli", requested=None):
    raise ValidationError("DHCP is off at this site: the scan runs in Kea's container, so nothing is scanned here")


out = answer([row("r14")], scanner=nokea)
check("any other refusal of the scan: answered refused with why", out["refused"] == ["r14"]
      and "DHCP is off at this site" in answered("r14")[4]["result"], (out, WRITES))

# ---- the plan poll runs them
print("--- the plan poll answers them (poll_plan)")
STATE = {"plan-watch": {"usn": 7, "kea": "k"}, "plan-dns": {}}
m_poll.load_watch_state = lambda name: dict(STATE.get(name) or {})
m_poll.save_watch_state = lambda name, data: STATE.__setitem__(name, dict(data))
m_poll.load_vars = lambda path: {}
m_poll.deploy_paths = lambda: {"vars": "none"}
ASKED = []


def scans_with(result):
    def run(v, secrets, container="samba"):
        ASKED.append(container)
        if isinstance(result, Exception):
            raise result
        return result
    return run


def poll(usn=7, result=None, read=None):
    return m_poll.poll_plan(V, container="dcx", secrets=SEC, usn=lambda c: usn,
                            read=read or (lambda *a, **k: 1 / 0), scans=scans_with(result or {"pending": False}))


quiet = poll()
check("the USN did not move and nothing is pending: the requests are not read", quiet["state"] == "unchanged"
      and not ASKED and "scans" not in quiet, (quiet, ASKED))
STATE["plan-watch"]["scan_pending"] = True
again = poll(result={"ran": ["r12"], "pending": False})
check("one still pending: read again though the USN did not move, the plan not read; the pending mark cleared",
      again["state"] == "unchanged" and ASKED == ["dcx"] and again["scans"]["ran"] == ["r12"]
      and STATE["plan-watch"]["scan_pending"] is False, (again, STATE))
STATE["plan-watch"]["scan_pending"] = True
try:
    poll(result=ValidationError("the domain controller is not running"))
    check("refused loudly: the requests not answered", False)
except ValidationError as e:
    check("refused loudly: the requests not answered, saying why; they stay pending for the next run",
          "the scan requests from other sites were not answered: the domain controller is not running" in str(e)
          and STATE["plan-watch"]["scan_pending"] is True, (e, STATE))
STATE["plan-watch"]["scan_pending"] = False
ASKED.clear()
same = {"sites": [{"name": "home", "block": 1}], "plans": {"home": {"vlans": [], "subnets": []}}}
moved = poll(usn=8, read=lambda v, s, of, container: same)
check("the USN moved: the requests answered in the same run, before Kea's part", ASKED == ["dcx"]
      and moved["scans"] == {"pending": False} and moved["state"] == "no subnet", (moved, ASKED))


# ---- `fabricctl ipam scan <subnet> --site S` and `scan-requests`
print("--- the command line")


def cli(*argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e):
        code = m_cmd.run_ipam_command(V, list(argv), secrets=SEC)
    return code, o.getvalue(), e.getvalue()


ROWS = []
m_rsc.request_scan = lambda v, actor, site, subnet, secrets, container: {
    "id": "scan-1", "site": site, "subnet": "cams", "cidr": "10.2.20.0/24", "state": "pending", "requested_by": "home",
    "actor": "root@dc1"}
m_rsc.list_scan_requests = lambda v, site, secrets, container: list(ROWS)
clock = {"t": 0.0}
real_run_scan_command = m_rsc.run_scan_command


def fixed_clock(*a, **k):
    return real_run_scan_command(*a, **k, sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
                                 clock=lambda: clock["t"])


m_cmd.run_scan_command = fixed_clock
code, o, e = cli("scan", "cams", "--site", "branch", "--no-wait")
check("fabricctl ipam scan --site --no-wait: requested, its id said, not awaited (exit 0)",
      code == 0 and "requested at branch: scan-1" in o and clock["t"] == 0, (code, o, e))
done = {**row("scan-1"), "state": "done", "late": False, "age": 20,
        "result": {"at": "2026-10-23T10:00", "scanned": 254, "answering": 1, "unrecorded": 1, "truncated": 0,
                   "rows": RESULT["answering"]}}
ROWS[:] = [done]
code, o, e = cli("scan", "cams", "--site", "branch")
check("fabricctl ipam scan --site: awaited, the answer shown (exit 0)", code == 0 and "10.2.20.5" in o
      and "IN USE, UNRECORDED" in o and clock["t"] == 5, (code, o, e))
ROWS[:] = [{**done, "state": "refused", "result": {"error": "no grant gives you networks scan at branch"}}]
code, o, e = cli("scan", "cams", "--site", "branch")
check("an answer that is not done: shown with why (exit 1)", code == 1 and "refused" in o and "no grant" in o,
      (code, o, e))
ROWS[:] = [{**done, "state": "pending", "result": None}]
clock["t"] = 0.0
code, o, e = cli("scan", "cams", "--site", "branch")
check("still pending when the wait ends: said, with where its answer will show (exit 0)", code == 0
      and "still pending after 120 s: fabricctl ipam scan-requests --site branch" in o, (code, o))
# covers: cli:ipam.scan-requests +
ROWS[:] = [done]
code, o, e = cli("scan-requests", "--site", "branch")
check("fabricctl ipam scan-requests --site: the requests and their answers (exit 0)", code == 0
      and "scan-1  10.2.20.0/24 (cams)  asked by root@dc1@home" in o and "10.2.20.5" in o, (code, o, e))
ROWS[:] = []
code, o, e = cli("scan-requests")
check("none: said for this site", code == 0 and "no scan requests at home in the last day" in o, (code, o))
# covers: cli:ipam.scan-requests -
code, o, e = cli("scan-requests", "extra")
check("scan-requests with a positional: the usage (exit 2)", code == 2 and "ipam scan-requests [--site S]" in e,
      (code, e))
code, o, e = cli("scan-requests", "--bogus")
check("an unknown option: refused, naming it (exit 1)", code == 1 and "unknown option --bogus" in e, (code, e))
code, o, e = cli("scan-requests", "--site")
check("--site without a value: refused (exit 1)", code == 1 and "--site needs a value" in e, (code, e))


def no_domain(v, site, secrets, container):
    raise ValidationError("the domain cannot be asked: fabric's secrets have no ad_agent_password")


m_rsc.list_scan_requests = no_domain
code, o, e = cli("scan-requests", "--site", "branch")
check("the domain not answering: refused, saying why (exit 1)", code == 1 and "ad_agent_password" in e, (code, e))


def no_request(v, actor, site, subnet, secrets, container):
    raise ValidationError("a scan of home's own subnet runs here: fabricctl ipam scan <subnet>")


m_rsc.request_scan = no_request
code, o, e = cli("scan", "cams", "--site", "home")
check("fabricctl ipam scan --site refused: said why (exit 1)", code == 1 and "runs here" in e, (code, e))
code, o, e = cli("scan", "--site", "branch")
check("fabricctl ipam scan --site without a subnet: the usage (exit 2)", code == 2 and "--site S [--no-wait]" in e,
      (code, e))

# ---- list_scan_requests: newest first, a day's worth, the late marked
rows = m_list.list_scan_requests(V, "branch", SEC, requests=lambda v, s, sec, c: [
    row("a", age=KEEP + 1), row("b", age=RUN_WITHIN + 1), row("c", age=5, state="done")], now=lambda: NOW)
check("the list: older than a day left out, newest first, a pending one past the hour marked late",
      [r["id"] for r in rows] == ["c", "b"] and rows[1]["late"] is True and rows[0]["late"] is False, rows)
seen = []
m_list.list_scan_requests(V, "", SEC, requests=lambda v, s, sec, c: seen.append(s) or [], now=lambda: NOW)
check("no site named: this site's", seen == ["home"], seen)

print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
