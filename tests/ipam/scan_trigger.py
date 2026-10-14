#!/usr/bin/env python3
"""The `ipam` suite, scans from the top down with no container (manual 1.10.4.29, decision 2.1.10.30): whether a site's
own admins may scan (the top always; elsewhere only when a site above allowed it; off by default), read from the DC,
the kept copy, or refused; a local scan refused where it is off, probing and auditing nothing, and a scan requested
from above run whatever it says; the setting set only from a site above (this site, a sibling refused before the
domain is asked); a scan asked from above (accepted; a sibling's, this site's, a subnet not in the branch's plan, a
second one pending, too many pending refused, writing nothing); the branch's poll answering requests (run, refused
when not made by a site above, expired after an hour, removed after a day, left pending while a scan runs, one per
run); the result's size bound; a round trip through a stand-in for AD with the poll's other steps stubbed; `fabricctl
ipam scan --site`, `scan-requests`, `local-scan`; the agent's routes and permissions; the console's card, buttons and
forms. The same at a real DC: tests/samba/ipam.py.

    python3 tests/ipam/scan_trigger.py
"""
import io
import json
import os
import re
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = tempfile.mkdtemp(prefix="fabric-scan-trigger-test-")
os.environ["DEPLOY_BASE_DIR"] = W               # the poll's kept state and vars.yaml go under the test's folder
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.ipam.poll_plan as m_poll  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_cmd  # noqa: E402
import fabriclib.ipam.scan_subnet as m_scan  # noqa: E402
import fabriclib.ipam.scancontrol.request_scan as m_req  # noqa: E402
import fabriclib.ipam.scancontrol.run_scan_command as m_run  # noqa: E402
import fabriclib.ipam.scancontrol.run_scan_requests as m_ans  # noqa: E402
from fabriclib.ipam.common.scan_busy import ScanBusy  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402
from fabriclib.ipam.scancontrol.bound_result import bound_result  # noqa: E402
from fabriclib.ipam.scancontrol.limits import KEEP, MAX_PENDING, RESULT_LIMIT, RUN_WITHIN  # noqa: E402
from fabriclib.ipam.scancontrol.list_scan_requests import list_scan_requests  # noqa: E402
from fabriclib.ipam.scancontrol.local_scan_state import local_scan_state  # noqa: E402
from fabriclib.ipam.scancontrol.read_local_scan import read_local_scan  # noqa: E402
from fabriclib.ipam.scancontrol.set_local_scan import set_local_scan  # noqa: E402
from fabriclib.ipam.scancontrol.show_local_scan import show_local_scan  # noqa: E402
from fabriclib.ipam.scancontrol.show_scan_requests import show_scan_requests  # noqa: E402
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


# the organisation: top above mid above house; house's sibling is cabin (below mid too); this install is top unless said
TOP, MID, HOUSE = {"site_name": "top", "install_kea": True}, {"site_name": "mid", "install_kea": True}, \
    {"site_name": "house", "install_kea": True}
BELOW = {"top": ["mid", "house", "cabin"], "mid": ["house", "cabin"], "house": [], "cabin": []}
ABOVE = {"top": [], "mid": ["top"], "house": ["mid", "top"], "cabin": ["mid", "top"]}


def scope(v, site):
    """site_scope's rule (the Networks tab's): this site or one below it, else refused."""
    want = site or v["site_name"]
    if want != v["site_name"] and want not in BELOW[v["site_name"]]:
        raise ValidationError(f"site {want!r} is not this site or one below it")
    return want


def levels(site, allowed=None, set_by="", top=False):
    entry = {"top": top, "set_by": set_by}
    if allowed is not None:
        entry["allowed"] = allowed
    return {site: entry}


# ---- whether a site's own admins may scan (1.10.4.29.4)
s = local_scan_state(levels("top", top=True), "top")
check("the top site: local scans always allowed", s["allowed"] and s["top"] and s["source"] == "the top site"
      and s["why"] == "", s)
s = local_scan_state({}, "house")
check("a site below, nothing set: off by default, saying the sites above decide and how they may scan there",
      not s["allowed"] and s["source"] == "default (off)" and "not set: off by default" in s["why"]
      and "--site house" in s["why"] and "Scan at house" in s["why"], s)
s = local_scan_state(levels("house", True, "mid alice 2026-10-13 10:00"), "house")
check("allowed from above: allowed, and who set it", s["allowed"] and s["set_by"].startswith("mid alice")
      and s["source"] == "set from above", s)
s = local_scan_state(levels("house", False, "top bob 2026-10-13 11:00"), "house")
check("denied from above: off, naming who set it", not s["allowed"] and "set by top bob" in s["why"], s)
s = local_scan_state(levels("house", "TRUE"), "house")
check("a value that is not exactly true counts as off (fails closed)", not s["allowed"], s)
s = local_scan_state(levels("cabin", True), "house")
check("another site's setting does not count for this one", not s["allowed"], s)
text = show_local_scan({**local_scan_state(levels("house", True, "mid alice"), "house"), "stale": "the DC was down"})
check("shown as text: allowed, who set it, the stale note", "local scans at house: allowed (set from above: mid "
      "alice)" in text and "set by the sites above it" in text and "note: the DC was down" in text, text)
text = show_local_scan({**local_scan_state(levels("top", top=True), "top"), "stale": ""})
check("shown as text at the top: always", "may always scan" in text, text)


def dc(lv):
    return lambda v, secrets, of="", container="samba": {"local_scan": lv}


def down(v, secrets, of="", container="samba"):
    raise ValidationError("the DC did not answer")


got = read_local_scan(HOUSE, read=dc(levels("house", True, "mid a")), cache=lambda: None)
check("read from the DC as this site's agent", got["allowed"] and got["stale"] == "", got)
got = read_local_scan(HOUSE, read=down, cache=lambda: {"site": "house", "read": "2026-10-13 09:00:00",
                                                        "local_scan": {"allowed": True, "set_by": "mid a"}})
check("the DC not answering: this site's kept copy, saying so and when", got["allowed"]
      and "2026-10-13 09:00:00" in got["stale"], got)
check("refused: the DC not answering and no kept copy (no local scan against a setting nobody could read)",
      refused(lambda: read_local_scan(HOUSE, read=down, cache=lambda: None), "cannot be read") is True)
check("refused: a kept copy from before the setting existed counts as none",
      refused(lambda: read_local_scan(HOUSE, read=down, cache=lambda: {"site": "house"}), "cannot be read") is True)
check("refused: another site's setting while the DC does not answer", refused(
    lambda: read_local_scan(TOP, "house", read=down, cache=lambda: {"local_scan": {}}), "cannot be read") is True)

# ---- a scan: local where allowed, from above always (1.10.4.29.1)
PLAN = {"site": "house", "block": 3, "vlans": [{"id": 20, "name": "iot", "access": "full"}],
        "subnets": [{"name": "iot", "cidr": "10.3.20.0/24", "vlan": 20, "gateway": "10.3.20.1", "dhcp": True, "id": 1,
                     "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "dhcp", "first": "10.3.20.100", "last": "10.3.20.249"}], "addresses": []},
                    {"name": "big", "cidr": "10.4.0.0/21", "vlan": 20, "gateway": "", "dhcp": False, "id": None,
                     "relay": "", "notes": "", "allow_overlap": "", "options": [], "ranges": [], "addresses": []}]}
HV = {**HOUSE, "dhcp": {"interfaces": ["eth0"], "subnets": plan_to_dhcp(PLAN)["subnets"]}}
PROBED, AUDIT = [], []
m_scan.write_audit = lambda actor, action, detail, source="cli", path=None: AUDIT.append((actor, action, detail,
                                                                                         source))
m_ans.write_audit = m_req.write_audit = m_scan.write_audit
SEEN = {"10.3.20.1": {"ping": True, "mac": ""}, "10.3.20.77": {"ping": True, "mac": "aa:bb:cc:00:00:77"}}


def probe(cidr, container):
    PROBED.append(cidr)
    return dict(SEEN)


def do_scan(v, actor, subnet, source="cli", local=None, requested=None):
    return m_scan.scan_subnet(v, actor, subnet, source=source, container="kt",
                              state_dir=os.path.join(W, f"state-{len(PROBED)}-{len(AUDIT)}"), probe=probe, leases=[],
                              local=local, cache=lambda: PLAN, requested=requested)


OFF = lambda v: {**local_scan_state({}, "house"), "stale": ""}                  # noqa: E731
ON = lambda v: {**local_scan_state(levels("house", True, "mid a"), "house"), "stale": ""}  # noqa: E731
# covers: cli:ipam.scan agent:post.ipam.scan -
why = refused(lambda: do_scan(HV, "alice", "iot", local=OFF), "local scans at house are off")
check("refused: a local scan where the sites above have not allowed it; nothing probed or audited",
      why is True and not PROBED and not AUDIT, (why, PROBED, AUDIT))
# covers: cli:ipam.scan agent:post.ipam.scan +
res = do_scan(HV, "alice", "iot", local=ON)
check("a local scan where a site above allowed it: run, saying what allowed it", PROBED == ["10.3.20.0/24"]
      and res["allowed"]["by"] == "local scans set from above" and AUDIT[-1][1] == "IPAM_SCAN"
      and "requested_by" not in AUDIT[-1][2], (res.get("allowed"), AUDIT[-1:]))
res = do_scan(HV, "carol@mid", "10.3.20.0/24", source="request", local=OFF,
              requested={"id": "scan-20261013100000-abcdef", "by": "mid"})
check("a scan requested from above runs although local scans are off; audited at the branch with who asked",
      res["allowed"]["by"] == "a request from mid" and AUDIT[-1][0] == "carol@mid"
      and "requested_by=mid request=scan-20261013100000-abcdef" in AUDIT[-1][2] and AUDIT[-1][3] == "request",
      AUDIT[-1])
state = os.path.join(W, "cool")
m_scan.scan_subnet(HV, "a", "iot", container="kt", state_dir=state, probe=probe, leases=[], local=ON,
                   cache=lambda: PLAN)
try:
    m_scan.scan_subnet(HV, "a", "iot", container="kt", state_dir=state, probe=probe, leases=[], local=ON,
                       cache=lambda: PLAN)
    busy = False
except ScanBusy as exc:
    busy = "scan it again in" in str(exc)
check("the same subnet within the minute: refused only for now (ScanBusy, a ValidationError)", busy)

# ---- setting it from above (1.10.4.29.4)
EDITS = []


LOCAL = {}                    # each branch's setting as AD keeps it (the value and who set it)


def fake_edit(v, actor, site, event, change, secrets=None, container="samba", source="cli"):
    """edit_options' stand-in: the branch's plan read with its local_scan (and the sites above it, nearest first)."""
    changes, result, detail, warnings = change({"local_scan": {**LOCAL.get(site, {}), "above": ABOVE.get(site, [])}})
    EDITS.append((v["site_name"], actor, site, event, changes, detail, source))
    LOCAL[site] = {"allowed": changes[0]["fields"]["allowed"], "set_by": changes[0]["fields"]["by"]}
    return {"result": result, "warnings": warnings, "done": ["set"], "site": site}


out = set_local_scan(MID, "alice", "house", "allow", source="web", edit=fake_edit, scope=scope)
check("a site above allows a branch's local scans: one local_scan change on the branch, audited, from the console",
      EDITS[-1][2:4] == ("house", "IPAM_LOCAL_SCAN_SET") and EDITS[-1][4][0]["what"] == "local_scan"
      and EDITS[-1][4][0]["site"] == "house" and EDITS[-1][4][0]["fields"]["allowed"] is True
      and EDITS[-1][4][0]["fields"]["by"].startswith("mid alice ") and EDITS[-1][6] == "web"
      and out["result"]["allowed"] is True, EDITS[-1])
set_local_scan(TOP, "bob", "house", "off", edit=fake_edit, scope=scope)
check("the top, two levels above, sets it too (off)", EDITS[-1][4][0]["fields"]["allowed"] is False
      and EDITS[-1][4][0]["fields"]["by"].startswith("top bob"), EDITS[-1])
before = len(EDITS)
for v, site, value, words in ((HOUSE, "house", "allow", "set by the sites above it"),
                              (HOUSE, "cabin", "allow", "not this site or one below it"),
                              (HOUSE, "mid", "allow", "not this site or one below it"),
                              (MID, "", "allow", "name the site below"),
                              (MID, "house", "maybe", "allowed, denied or cleared")):
    check(f"refused: {v['site_name']} setting {site or '(none)'}'s local scans to {value}, saying why",
          refused(lambda: set_local_scan(v, "x", site, value, edit=fake_edit, scope=scope), words) is True)
check("a refused setting writes nothing", len(EDITS) == before)

# the highest site above that set it wins (the owner's answer of 2026-10-13, 2.1.10.30 revised)
LOCAL.clear()
set_local_scan(MID, "alice", "house", "allow", edit=fake_edit, scope=scope)
set_local_scan(TOP, "bob", "house", "deny", edit=fake_edit, scope=scope)
s = local_scan_state({"house": {**LOCAL["house"], "top": False}}, "house")
check("the top's deny beats the region's allow: off, set by the top", not s["allowed"]
      and s["set_by"].startswith("top bob"), s)
before = len(EDITS)
why = refused(lambda: set_local_scan(MID, "alice", "house", "allow", edit=fake_edit, scope=scope),
              "were set by top, above mid: only top or a site above it may change them")
check("refused: the region changing a value the top set, naming the top; nothing written", why is True
      and len(EDITS) == before and LOCAL["house"]["set_by"].startswith("top"), why)
set_local_scan(TOP, "bob", "house", "allow", edit=fake_edit, scope=scope)
check("the top changes its own value", LOCAL["house"]["allowed"] is True, LOCAL)
set_local_scan(MID, "alice", "cabin", "allow", edit=fake_edit, scope=scope)
set_local_scan(MID, "alice", "cabin", "deny", edit=fake_edit, scope=scope)
check("the region sets a branch where the top has not, and changes its own value", LOCAL["cabin"]["allowed"] is False
      and LOCAL["cabin"]["set_by"].startswith("mid alice"), LOCAL)
set_local_scan(TOP, "bob", "cabin", "allow", edit=fake_edit, scope=scope)
check("the top overrides the region's value (and from then on holds it)", LOCAL["cabin"]["set_by"].startswith("top")
      and refused(lambda: set_local_scan(MID, "a", "cabin", "deny", edit=fake_edit, scope=scope), "set by top")
      is True, LOCAL)
check("refused: a site that is not above the branch in the domain (the registry and AD disagreeing)", refused(
    lambda: set_local_scan(MID, "a", "house", "allow", edit=lambda v, a, s, e, change, *x, **k: change(
        {"local_scan": {"above": ["region2", "top"]}}), scope=scope), "mid is not above house in the domain") is True)
# clear (the coordinator, 2026-10-13): whoever may set it may remove it
EV = []
set_local_scan(TOP, "bob", "house", "clear", edit=lambda v, a, s, e, change, *x, **k: EV.append(e) or fake_edit(
    v, a, s, e, change, *x, **k), scope=scope)
check("the top clears its own value: removed (off by default), audited IPAM_LOCAL_SCAN_CLEAR, what it was in the "
      "audit", LOCAL["house"] == {"allowed": None, "set_by": ""} and EV == ["IPAM_LOCAL_SCAN_CLEAR"]
      and EDITS[-1][5].startswith("cleared (was top bob"), (LOCAL, EV, EDITS[-1]))
set_local_scan(MID, "alice", "house", "allow", edit=fake_edit, scope=scope)
check("then the region may set it again", LOCAL["house"]["set_by"].startswith("mid"), LOCAL)
set_local_scan(TOP, "bob", "house", "deny", edit=fake_edit, scope=scope)
before = len(EDITS)
check("refused: the region clearing the top's value, naming the top; nothing written", refused(
    lambda: set_local_scan(MID, "a", "house", "clear", edit=fake_edit, scope=scope), "were set by top") is True
    and len(EDITS) == before)
LOCAL["cabin"] = {"allowed": True, "set_by": "mid alice 2026-10-13 10:00"}
set_local_scan(TOP, "bob", "cabin", "clear", edit=fake_edit, scope=scope)
check("the top clears a value the region set (a site above the setter)", LOCAL["cabin"]["set_by"] == "", LOCAL)
before = len(EDITS)
check("refused: clearing where nothing is set, saying so", refused(
    lambda: set_local_scan(TOP, "bob", "cabin", "clear", edit=fake_edit, scope=scope), "nothing to clear") is True
    and len(EDITS) == before)
LOCAL.clear()


# ---- a stand-in for AD's requests (the DC's read_scan_requests and write_scan_request, 1.10.4.29.2)
CLOCK = {"t": 1_800_000_000.0}
OWNER = {}


class FakeAD:
    def __init__(self):
        self.rows, self.writes = {}, []

    def write(self, v, secrets, do, site, subnet, rid, fields=None, container="samba"):
        self.writes.append((v["site_name"], do, site, rid, dict(fields or {})))
        if do == "add":                           # AD: only a site above the branch may create one
            if v["site_name"] not in ABOVE[site]:
                raise ValidationError("the directory refused the change (not permitted for this site)")
            self.rows[rid] = {"id": rid, "site": site, "subnet": subnet, "cidr": fields["cidr"],
                              "requested_by": v["site_name"], "actor": fields["actor"], "state": "pending",
                              "result": None, "done_at": "", "created": "2027-01-15T08:00:00Z",
                              "created_at": CLOCK["t"], "owner": OWNER.get(rid, f"fabric-agent-{v['site_name']}")}
        elif do == "finish":
            r = self.rows[rid]
            try:
                result = json.loads(fields["result"])
            except ValueError:
                result = {"error": fields["result"]}
            r.update(state=fields["state"], result=result, done_at=fields["done_at"])
        elif do == "remove":
            del self.rows[rid]
        return do

    def read(self, v, site, secrets=None, container="samba"):
        out = []
        for r in self.rows.values():
            if r["site"] == site:
                ok = r["requested_by"] in ABOVE[site] and r["owner"] == f"fabric-agent-{r['requested_by']}"
                out.append({**r, "from_above": ok})
        return sorted(out, key=lambda r: (r["created_at"], r["id"]))


AD = FakeAD()


def plan_of(v, secrets, of="", container="samba"):
    return {"sites": [{"name": of, "block": 3}], "plans": {of: PLAN}}


def ask(v, site, subnet, actor="alice"):
    return m_req.request_scan(v, actor, site, subnet, secrets={}, read=plan_of, requests=AD.read, write=AD.write,
                              scope=scope, now=lambda: CLOCK["t"])


# ---- asking from above (1.10.4.29.3)
# covers: cli:ipam.scan agent:post.ipam.scan.request +
r1 = ask(MID, "house", "iot")
check("a site above asks a branch to scan one of its subnets: written into AD below that subnet, pending, audited "
      "here", re.match(r"^scan-[0-9]{14}-[0-9a-f]{6}$", r1["id"]) and r1["cidr"] == "10.3.20.0/24"
      and AD.rows[r1["id"]]["state"] == "pending" and AD.writes[-1][:3] == ("mid", "add", "house")
      and AUDIT[-1][1] == "IPAM_SCAN_REQUEST" and "from=mid site=house subnet=10.3.20.0/24" in AUDIT[-1][2], (r1, AUDIT[-1]))
CLOCK["t"] += 1
READS = []


def plan_counted(v, secrets, of="", container="samba"):
    READS.append(of)
    return plan_of(v, secrets, of, container)


# covers: cli:ipam.scan agent:post.ipam.scan.request -
n_writes = len(AD.writes)
for v, site, subnet, words in ((HOUSE, "cabin", "iot", "not this site or one below it"),
                               (HOUSE, "mid", "iot", "not this site or one below it"),
                               (MID, "mid", "iot", "runs here"),
                               (MID, "", "iot", "name the site below")):
    check(f"refused before the domain is asked: {v['site_name']} asking {site or '(none)'}", refused(
        lambda: m_req.request_scan(v, "x", site, subnet, secrets={}, read=plan_counted, requests=AD.read,
                                   write=AD.write, scope=scope), words) is True and not READS)
for subnet, words in (("10.9.9.0/24", "not a subnet of house's plan"), ("nosuch", "not a subnet of house's plan"),
                      ("10.3.20.5/24", "host bits zero"), ("", "name the subnet"), ("big", "larger than a /22"),
                      ("iot", "already pending")):
    check(f"refused: asking house to scan {subnet!r}, saying why", refused(lambda: ask(MID, "house", subnet), words)
          is True)
check("nothing written for a refused request", len(AD.writes) == n_writes, AD.writes[n_writes:])
PLAN["subnets"] += [{**PLAN["subnets"][0], "name": f"s{i}", "cidr": f"10.3.{30 + i}.0/24"} for i in range(4)]
for i in range(MAX_PENDING - 1):
    ask(TOP, "house", f"s{i}")
check(f"refused: a {MAX_PENDING + 1}th pending request at one branch", refused(
    lambda: ask(TOP, "house", "s3"), f"{MAX_PENDING} scans are already pending") is True)

# ---- the branch's poll answers them (run_scan_requests)
for rid in list(AD.rows):
    if rid != r1["id"]:
        del AD.rows[rid]


def answer(v=HV, scan=None):
    return m_ans.run_scan_requests(v, {}, requests=AD.read, write=AD.write, now=lambda: CLOCK["t"],
                                   scan=scan or (lambda v, actor, subnet, source="cli", requested=None:
                                                 do_scan(v, actor, subnet, source, OFF, requested)))


PROBED.clear()
out = answer()
row = AD.rows[r1["id"]]
check("the branch's poll runs a request from above (local scans off) and writes the answer back on it",
      out["ran"] == [r1["id"]] and PROBED == ["10.3.20.0/24"] and row["state"] == "done"
      and row["result"]["rows"][0]["status"] == "unrecorded" and row["result"]["unrecorded"] == 1
      and row["done_at"], (out, row))
check("answered: audited at the branch as the asking person at the asking site",
      AUDIT[-1][0] == "alice@mid" and AUDIT[-1][1] == "IPAM_SCAN" and "requested_by=mid" in AUDIT[-1][2], AUDIT[-1])
listed = list_scan_requests(MID, "house", requests=AD.read, scope=scope, now=lambda: CLOCK["t"])
check("round trip: the asking site reads the answer back from AD (the console's and the command's list)",
      listed[0]["id"] == r1["id"] and listed[0]["state"] == "done" and listed[0]["result"]["rows"][0]["ip"]
      == "10.3.20.77" and not listed[0]["late"], listed)
text = show_scan_requests("house", listed)
check("shown as text: who asked, the state, every address that answered, the unrecorded marked",
      "asked by alice@mid" in text and ": done" in text and "IN USE, UNRECORDED" in text, text)
check("answered requests are not run again", answer()["ran"] == [] and len(PROBED) == 1)
check("refused: a sibling's console listing the branch's requests", refused(
    lambda: list_scan_requests(HOUSE, "cabin", requests=AD.read, scope=scope), "not this site or one below") is True)

# a request the branch's own agent made (AD denies it; one slipped in by hand is never run)
forged = "scan-20270115080000-0f0f0f"
OWNER[forged] = "fabric-agent-house"
AD.write(MID, {}, "add", "house", "iot", forged, {"cidr": "10.3.20.0/24", "actor": "eve"})
n_probed = len(PROBED)
out = answer()
check("refused at the branch: a request not made by the agent of a site above, never run, audited",
      out["refused"] == [forged] and len(PROBED) == n_probed and AD.rows[forged]["state"] == "refused"
      and "not requested by a site above house" in AD.rows[forged]["result"]["error"]
      and AUDIT[-1][1] == "IPAM_SCAN_REQUEST_REFUSED", (out, AD.rows[forged]))
CLOCK["t"] += RUN_WITHIN + 5
late = ask(TOP, "house", "s0")
CLOCK["t"] += RUN_WITHIN + 5
out = answer()
check("a request still pending after an hour: answered expired, not run", out["expired"] == [late["id"]]
      and AD.rows[late["id"]]["state"] == "expired" and len(PROBED) == n_probed, out)
CLOCK["t"] += KEEP
out = answer()
check("a day on: every request removed by the branch's poll, whatever its state",
      set(out["removed"]) == {r1["id"], forged, late["id"]} and not AD.rows, out)
a, b = ask(TOP, "house", "s1"), ask(TOP, "house", "s2")


def busy(v, actor, subnet, source="cli", requested=None):
    raise ScanBusy("another scan is running: try again when it ends")


out = answer(scan=busy)
check("another scan running at the branch: the requests stay pending for the next run", out["pending"] is True
      and AD.rows[a["id"]]["state"] == AD.rows[b["id"]]["state"] == "pending", out)
out = answer()
check("one request run per poll run; the rest left pending, and said so", len(out["ran"]) == 1 and out["pending"],
      out)
out = answer()
check("the next run takes the next one", len(out["ran"]) == 1 and not out["pending"], out)
c = ask(TOP, "house", "s3")


def nokea(v, actor, subnet, source="cli", requested=None):
    raise ValidationError("DHCP is off at this site: the scan runs in Kea's container, so nothing is scanned here")


out = answer(scan=nokea)
check("a request the branch cannot run (no Kea there): answered refused with why, audited", out["refused"] == [c["id"]]
      and "DHCP is off" in AD.rows[c["id"]]["result"]["error"] and AUDIT[-1][1] == "IPAM_SCAN_REQUEST_REFUSED", out)

# ---- the result's size bound
BIG = {"subnet": {"name": "big", "cidr": "10.4.0.0/22"}, "at": "2026-10-13T10:00:00", "scanned": 1022,
       "unrecorded": 3,
       "answering": [{"ip": f"10.4.{i // 256}.{i % 256}", "mac": f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}",
                      "how": "ping+arp", "status": "unrecorded" if i in (900, 901, 902) else "recorded",
                      "kind": "" if i in (900, 901, 902) else "static", "name": "" if i in (900, 901, 902)
                      else f"device-with-a-long-name-{i}", "note": "answered from another MAC than the plan's" * 2}
                     for i in range(1, 1022)]}
text = bound_result(BIG)
got = json.loads(text)
check(f"a /22 answering everywhere: the result kept within {RESULT_LIMIT} characters, the rows left out counted, the "
      "unrecorded first", len(text) <= RESULT_LIMIT and got["truncated"] > 0 and got["answering"] == 1021
      and len(got["rows"]) + got["truncated"] == 1021 and [r["ip"] for r in got["rows"][:3]]
      == ["10.4.3.132", "10.4.3.133", "10.4.3.134"], (len(text), got["truncated"]))
small = json.loads(bound_result(res))
check("a small result kept whole", small["truncated"] == 0 and len(small["rows"]) == len(res["answering"]))
try:
    bound_result(BIG, limit=50)
    tiny = False
except ValueError:
    tiny = True
check("a limit too small for the summary: refused loudly", tiny)

# ---- the plan poll calls the step (1.10.4.26)
os.makedirs(os.path.join(W, "fabric", "config"), exist_ok=True)
with open(os.path.join(W, "fabric", "config", "vars.yaml"), "w") as f:
    f.write("dhcp:\n  interfaces: [eth0]\n")
STEPS = []


def scans(result):
    def run(v, secrets, container="samba"):
        STEPS.append(v["site_name"])
        return result
    return run


def poll(result, usn=5):
    return m_poll.poll_plan(HV, container="none", secrets={}, usn=lambda c: usn, scans=scans(result),
                            read=lambda *a, **k: 1 / 0)


from fabriclib.ipam.options.watch_state import save_watch_state  # noqa: E402
save_watch_state("plan-watch", {"usn": 5})
check("the USN unmoved and nothing pending: the requests are not read", poll({"pending": False})["state"]
      == "unchanged" and not STEPS)
save_watch_state("plan-watch", {"usn": 5, "scan_pending": True})
got = poll({"ran": ["x"], "pending": False})
check("the USN unmoved but a request left pending: the requests read and answered, the plan not", STEPS == ["house"]
      and got["state"] == "unchanged" and got["scans"]["ran"] == ["x"], got)
check("then nothing pending is kept, so the next quiet run reads nothing", poll({"pending": False})["state"]
      == "unchanged" and STEPS == ["house"])
save_watch_state("plan-watch", {"usn": 5, "scan_pending": True})
check("the requests not answerable (the DC refusing): the run fails loudly, saying so", refused(
    lambda: m_poll.poll_plan(HV, container="none", secrets={}, usn=lambda c: 5,
                             scans=lambda v, s, container="samba": (_ for _ in ()).throw(ValidationError("DC down")))
    , "the scan requests from above were not answered: DC down") is True)


# ---- the command line (1.10.4.29.5)
def cli(v, *argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e):
        code = m_cmd.run_ipam_command(v, list(argv))
    return code, o.getvalue(), e.getvalue()


m_run.request_scan = lambda v, actor, site, subnet, secrets=None, container="samba": ask(v, site, subnet, actor)
m_run.list_scan_requests = lambda v, site="", secrets=None, container="samba": list_scan_requests(
    v, site, requests=AD.read, scope=scope, now=lambda: CLOCK["t"])
m_run.set_local_scan = lambda v, actor, site, allowed, secrets=None, container="samba": set_local_scan(
    v, actor, site, allowed, edit=fake_edit, scope=scope)
m_run.read_local_scan = lambda v, site="", secrets=None, container="samba": {
    **local_scan_state(levels("house", True, "top root"), site or v["site_name"]), "stale": ""}
AD.rows.clear()
TICK = {"n": 0}


def sleep(s):          # the branch's poll answers while the command waits
    TICK["n"] += 1
    if TICK["n"] == 2:
        answer()


m_run.time = type("T", (), {"sleep": staticmethod(sleep), "monotonic": staticmethod(lambda: TICK["n"])})
o, e = io.StringIO(), io.StringIO()
with redirect_stdout(o), redirect_stderr(e):
    code = m_run.run_scan_command(TOP, "scan", ["iot", "--site", "house"], sleep=sleep, clock=lambda: TICK["n"])
check("fabricctl ipam scan iot --site house: requested, the answer awaited and shown (exit 0)", code == 0
      and "requested at house" in o.getvalue() and ": done" in o.getvalue()
      and "IN USE, UNRECORDED" in o.getvalue(), (code, o.getvalue(), e.getvalue()))
# covers: cli:ipam.scan-requests +
code, o, e = cli(TOP, "scan-requests", "--site", "house")
check("fabricctl ipam scan-requests --site house: the answers", code == 0 and "asked by root@top" in o, (o, e))
code, o, e = cli(TOP, "scan", "s0", "--site", "house", "--no-wait")
check("--no-wait: only asked", code == 0 and "requested at house" in o and "done" not in o, (o, e))
# covers: cli:ipam.scan-requests -
code, o, e = cli(HOUSE, "scan-requests", "--site", "cabin")
check("scan-requests --site of a sibling: refused (exit 1)", code == 1 and "not this site or one below" in e, e)
code, o, e = cli(TOP, "scan-requests", "extra")
check("scan-requests with an extra word: the usage (exit 2)", code == 2 and "fabricctl ipam scan-requests" in e, e)
code, o, e = cli(HOUSE, "scan", "iot", "--site", "cabin")
check("fabricctl ipam scan --site of a sibling: refused (exit 1)", code == 1 and "not this site or one below" in e, e)
# covers: cli:ipam.local-scan +
code, o, e = cli(HOUSE, "local-scan")
check("fabricctl ipam local-scan: here, allowed or not and who set it", code == 0
      and "local scans at house: allowed (set from above: top root)" in o, (o, e))
code, o, e = cli(MID, "local-scan", "allow", "--site", "house")
check("fabricctl ipam local-scan allow --site house, from above", code == 0 and "local scans at house: allowed" in o
      and EDITS[-1][4][0]["fields"]["allowed"] is True, (o, e))
code, o, e = cli(MID, "local-scan", "clear", "--site", "house")
check("fabricctl ipam local-scan clear --site house, by the site that set it", code == 0 and "cleared" in o
      and LOCAL["house"]["set_by"] == "", (o, e))
code, o, e = cli(MID, "local-scan", "clear", "--site", "house")
check("local-scan clear with nothing set: refused (exit 1)", code == 1 and "nothing to clear" in e, e)
# covers: cli:ipam.local-scan -
for v, argv, words, want in ((HOUSE, ("local-scan", "allow", "--site", "house"), "set by the sites above it", 1),
                             (HOUSE, ("local-scan", "allow", "--site", "cabin"), "not this site or one below", 1),
                             (MID, ("local-scan", "allow"), "name the site below", 1),
                             (MID, ("local-scan", "--colour"), "unknown option --colour", 1),
                             (MID, ("local-scan", "sometimes", "--site", "house"), "fabricctl ipam local-scan", 2)):
    code, o, e = cli(v, *argv)
    check(f"{v['site_name']}: {' '.join(argv)}: refused (exit {want}), saying why", code == want and words in e,
          (code, e))
check("the usage lists the new commands, and scan-policy is gone", "local-scan" in m_cmd.USAGE
      and "scan-policy" not in m_cmd.USAGE and "fabricctl ipam scan-requests" in m_run.USAGE)

# ---- the agent: permissions and routes
check("permissions: asking a scan below and setting its local scans need dhcp:write; the old routes are gone",
      required_permission("POST", ["ipam", "scan", "request"]) == "dhcp:write"
      and required_permission("POST", ["ipam", "local-scan"]) == "dhcp:write"
      and required_permission("POST", ["ipam", "scan-policy"]) is None
      and required_permission("POST", ["ipam", "scan-policy", "org"]) is None)
# covers: agent:post.ipam.scan.request agent:post.ipam.local-scan -
check("refused: the auditor holds no dhcp:write (403 for both routes); a network operator holds it",
      "dhcp:write" not in BUNDLES["fabric-auditor"] and "dhcp:write" in BUNDLES["fabric-network-operator"])
try:
    import agent.post_ipam_scan as m_agent_scan  # noqa: E402
    import agent.post_local_scan as m_agent_local  # noqa: E402
    from agent.route_not_found import RouteNotFound  # noqa: E402
    agent_ok = True
except ImportError as exc:          # the agent's imports need the host's modules (yaml, ...)
    agent_ok, why = False, exc
if agent_ok:
    CALLS = []
    m_agent_scan.load_vars = m_agent_local.load_vars = lambda: TOP

    def fake_request(v, actor, site, subnet, source="cli"):
        scope(v, site)
        CALLS.append(("request", actor, site, subnet, source))
        return {"id": "scan-20261013100000-abcdef", "site": site, "subnet": subnet, "cidr": "10.3.20.0/24",
                "state": "pending"}

    def fake_local(v, actor, site, allowed, source="cli"):
        scope(v, site)
        CALLS.append(("local", actor, site, allowed, source))
        return {"result": {"site": site, "allowed": allowed, "set_by": "top alice"}}

    m_agent_scan.request_scan = fake_request
    m_agent_local.set_local_scan = fake_local
    # covers: agent:post.ipam.scan.request +
    m_agent_scan.post_ipam_scan(["ipam", "scan", "request"], "alice", {"site": "house", "subnet": "iot"})
    check("POST /v1/ipam/scan/request: the site and subnet passed on, from the web",
          CALLS[-1] == ("request", "alice", "house", "iot", "web"), CALLS[-1:])
    # covers: agent:post.ipam.local-scan +
    m_agent_local.post_local_scan(["ipam", "local-scan"], "alice", {"site": "house", "allowed": "on"})
    check("POST /v1/ipam/local-scan: on", CALLS[-1] == ("local", "alice", "house", True, "web"), CALLS[-1:])
    m_agent_local.post_local_scan(["ipam", "local-scan"], "alice", {"site": "house", "allowed": "clear"})
    check("POST /v1/ipam/local-scan: clear", CALLS[-1] == ("local", "alice", "house", "clear", "web"), CALLS[-1:])
    n = len(CALLS)
    # covers: agent:post.ipam.scan.request -
    m_agent_scan.load_vars = m_agent_local.load_vars = lambda: HOUSE
    check("refused: a request for a sibling (400), before the domain is asked", refused(
        lambda: m_agent_scan.post_ipam_scan(["ipam", "scan", "request"], "alice", {"site": "cabin", "subnet": "iot"}),
        "not this site or one below") is True and len(CALLS) == n)
    check("refused: a field that is not text", refused(lambda: m_agent_scan.post_ipam_scan(
        ["ipam", "scan", "request"], "alice", {"site": ["house"], "subnet": "iot"}), "must be text") is True)
    # covers: agent:post.ipam.local-scan -
    check("refused: allowed neither on nor off", refused(lambda: m_agent_local.post_local_scan(
        ["ipam", "local-scan"], "alice", {"site": "house", "allowed": "yes"}), "allowed is on, off or clear") is True
        and len(CALLS) == n)
    check("refused: a sibling's local scans", refused(lambda: m_agent_local.post_local_scan(
        ["ipam", "local-scan"], "alice", {"site": "cabin", "allowed": "on"}), "not this site") is True)
    try:
        m_agent_local.post_local_scan(["ipam", "local-scan", "x"], "alice", {})
        nf = False
    except RouteNotFound:
        nf = True
    check("another route under ipam/local-scan: not found (404)", nf)
else:
    check("the agent's routes import", False, why)

# ---- the console: the card, the buttons, the forms, the scan page
sys.path.insert(0, REPO)
try:
    from webui import agentclient as actions  # noqa: E402
    from webui import views  # noqa: E402
    import webui.routes.networks_scan_post as m_post  # noqa: E402
    from fabriclib.ipam.networks_view import networks_view  # noqa: E402
    web_ok = True
except ImportError as exc:          # jinja2 missing on this machine
    web_ok, why = False, exc


class H:
    def __init__(self):
        self.sent = self.to = None

    def send(self, code, body):
        self.sent = (code, body)

    def redirect(self, url, headers=None):
        self.to = url

    def deny(self, code, text):
        self.sent = (code, text)


if web_ok:
    READ = {"sites": [{"name": "top", "created": "1", "block": 1}, {"name": "house", "created": "2", "block": 3}],
            "plans": {"house": {"vlans": PLAN["vlans"], "subnets": PLAN["subnets"][:1], "networks": []},
                      "top": {"vlans": [], "subnets": [], "networks": []}}}
    SITES = [{"name": "top", "own": True}, {"name": "house", "own": False}]
    CTX = {"user": "alice", "csrf": "tok", "perms": ["dhcp:read", "dhcp:write"], "version": "0.8.0"}
    DONE = AD.read(TOP, "house")

    def tab(site, local, perms, requests=(), subnet="iot"):
        ov = networks_view({**TOP, "dhcp": {}}, READ, site, SITES, None)
        ov.update(own="top", stale="", error="", leases_error="", sync=None, local_scan=local,
                  scan_requests=list(requests), scan_requests_error="")
        return views.networks({**CTX, "perms": perms}, ov, subnet)

    below = {**local_scan_state({}, "house"), "settable": True}
    page = tab("house", below, CTX["perms"], DONE)
    # covers: web:post.networks.scan.request web:post.networks.scan.local +
    check("the Networks tab on a site below: Scans at house (off by default), the form, the requests with answers, "
          "and the subnet's Scan at house button", "Scans at house" in page and "not set by the sites above: off by "
          "default" in page and 'action="/networks/scan/local"' in page and 'action="/networks/scan/request"' in page
          and "Scan at house" in page and "unrecorded" in page and "root@top" in page
          and "Scan this subnet" not in page, [w for w in ("Scans at house", "off by default", "/networks/scan/local",
                                                           "/networks/scan/request", "unrecorded", "root@top")
                                                 if w not in page])
    # covers: web:post.networks.scan.request web:post.networks.scan.local -
    page = tab("house", {**below, "set_by": "top bob 2026-10-13 10:00"}, CTX["perms"], DONE)
    check("a value set from above: the card's Clear button, naming who may clear it", 'value="clear"' in page
          and "only top or a site above it may" in page)
    check("nothing set: no Clear button", 'value="clear"' not in tab("house", below, CTX["perms"], DONE))
    page = tab("house", below, ["dhcp:read"], DONE)
    check("without dhcp:write: the card and the answers read-only, no form, no Scan at button",
          "Scans at house" in page and "/networks/scan/local" not in page and "/networks/scan/request" not in page)
    top = {**local_scan_state(levels("top", top=True), "top"), "settable": False}
    READ["plans"]["top"] = {"vlans": PLAN["vlans"], "subnets": [{**PLAN["subnets"][0], "name": "iot"}], "networks": []}
    page = tab("top", top, CTX["perms"])
    check("this site, the top: always allowed, no form, the Scan this subnet link, no Scan at button",
          "the top site: its admins may always scan" in page and "/networks/scan/local" not in page
          and "Scan this subnet" in page and "/networks/scan/request" not in page, page[:3000])
    m_post.page_context = lambda sess: CTX
    off = {**local_scan_state({}, "house"), "stale": ""}
    page = views.ipam_scan(CTX, [{"name": "iot", "cidr": "10.3.20.0/24", "vlan": 20, "dhcp": True, "hosts": 254}],
                           None, local=off)
    check("the scan page at a branch with local scans off: why, who decides, and no Scan button",
          "local scans at house are off" in page and "Scan now" not in page and "set by the sites above it" in page,
          page[-1500:])
    page = views.ipam_scan(CTX, [{"name": "iot", "cidr": "10.3.20.0/24", "vlan": 20, "dhcp": True, "hosts": 254}],
                           None, local=None, local_error="whether local scans are allowed at house cannot be read")
    check("the scan page when the setting cannot be read: says so, no Scan button", "cannot be read" in page
          and "Scan now" not in page)
    ASKED = []

    def fake_req(site, subnet):
        ASKED.append((site, subnet))
        if site == "cabin":
            raise actions.ValidationError("site 'cabin' is not this site or one below it")
        return {"id": "scan-20261013100000-abcdef", "site": site, "subnet": "iot", "cidr": "10.3.20.0/24"}

    def fake_set(site, allowed):
        ASKED.append((site, allowed))
        if allowed not in ("on", "off"):
            raise actions.ValidationError("allowed is on or off")
        return {"result": {"site": site, "allowed": allowed == "on", "set_by": "top alice"}}

    actions.request_scan, actions.set_local_scan = fake_req, fake_set
    h = H()
    m_post.networks_scan_post(h, {}, ["request"], {"site": "house", "subnet": "iot", "cidr": "10.3.20.0/24"})
    check("Scan at house: asked through the agent, back to that site's subnet saying where the answer shows",
          ASKED[-1] == ("house", "10.3.20.0/24") and h.to.startswith("/networks?site=house&subnet=iot&msg=")
          and "Scans+at+house" in h.to, h.to)
    h = H()
    m_post.networks_scan_post(h, {}, ["request"], {"site": "cabin", "subnet": "iot"})
    check("a request the agent refuses: back with why", "err=" in h.to and "one+below" in h.to, h.to)
    h = H()
    m_post.networks_scan_post(h, {}, ["local"], {"site": "house", "allowed": "on"})
    check("the local scans form: set, back to the site saying what it is now", ASKED[-1] == ("house", "on")
          and h.to.startswith("/networks?site=house&msg=") and "allowed" in h.to, h.to)
    h = H()
    actions.set_local_scan = lambda site, allowed: {"result": {"site": site, "allowed": None, "set_by": ""}}
    m_post.networks_scan_post(h, {}, ["local"], {"site": "house", "allowed": "clear"})
    check("the Clear button: back to the site saying it is off by default", "cleared" in h.to, h.to)
    actions.set_local_scan = fake_set
    h = H()
    m_post.networks_scan_post(h, {}, ["local"], {"site": "house", "allowed": "maybe"})
    check("a value the agent refuses: back with why", "err=" in h.to and "on+or+off" in h.to, h.to)
    h = H()
    m_post.networks_scan_post(h, {}, ["policy"], {"site": "house", "policy": "deny"})
    check("the old scan policy form is gone (404)", h.sent and h.sent[0] == 404, h.sent)
else:
    print(f"SKIP the console's scans from the top down: {why}")

print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
