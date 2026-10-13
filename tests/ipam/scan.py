#!/usr/bin/env python3
"""The `ipam` suite, the scan and ping-check with no container (manual 1.10.4.22, 1.10.4.27; decisions 2.1.10.13,
2.1.10.26 and 2.1.10.28): a scan's subnet chosen among every subnet of this site's plan, DHCP on or off (by name or
exact network; bad input, a subnet not in the plan, one larger than a /22 and a site without Kea refused), the scan
policy asked before anything is probed (its own cases: tests/ipam/scan_policy.py), one scan at a time and once a minute per subnet, what
answered classified against the plan and Kea's leases (a declined lease is in use, unrecorded), audited; the network
probe's fixed argument list run in Kea's container; the neighbour table read; the text shown; the terminal's offer to
record each find through the reservation unit; `fabricctl ipam scan`'s refusals; the agent's permissions (a user
without dhcp:write refused) and its record route's refusals; the console's scan page and its refusals; the
`dhcp.ping_check` setting and the Kea template's ping-check hook. The real network: tests/kea/scan.py.

    python3 tests/ipam/scan.py
"""
import fcntl
import io
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp  # noqa: E402
import fabriclib.ipam.common.probe_subnet as m_probe  # noqa: E402
import fabriclib.ipam.offer_reservations as m_offer  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_cmd  # noqa: E402
import fabriclib.ipam.scan_subnet as m_scan  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402
from fabriclib.ipam.scannable_subnets import scannable_subnets  # noqa: E402
from fabriclib.ipam.show_scan import show_scan  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

FAILED = 0
TMP = tempfile.mkdtemp(prefix="fabric-scan-test-")


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


PLAN = {"site": "home", "block": 1, "vlans": [{"id": 20, "name": "iot", "access": "full"},
                                             {"id": 30, "name": "big", "access": "full"}],
        "subnets": [{"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "gateway": "10.1.20.1", "dhcp": True, "id": 1,
                     "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "static", "first": "10.1.20.2", "last": "10.1.20.99"},
                                {"kind": "dhcp", "first": "10.1.20.100", "last": "10.1.20.249"}],
                     "addresses": [{"ip": "10.1.20.10", "kind": "static", "name": "nas", "mac": "", "dns": True,
                                    "options": []},
                                   {"ip": "10.1.20.150", "kind": "reservation", "name": "cam1",
                                    "mac": "aa:bb:cc:00:00:01", "dns": False, "options": []}]},
                    {"name": "big", "cidr": "10.1.32.0/21", "vlan": 30, "gateway": "10.1.32.1", "dhcp": True, "id": 2,
                     "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "dhcp", "first": "10.1.33.0", "last": "10.1.36.255"}], "addresses": []},
                    # a static-only VLAN: DHCP off, devices set by hand (2.1.10.28)
                    {"name": "lab", "cidr": "10.1.40.0/24", "vlan": 40, "gateway": "10.1.40.1", "dhcp": False,
                     "id": 3, "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "static", "first": "10.1.40.2", "last": "10.1.40.254"}],
                     "addresses": [{"ip": "10.1.40.10", "kind": "static", "name": "plc", "mac": "", "dns": False,
                                    "options": []}]}]}
V = {"site_name": "home", "install_kea": True,
     "dhcp": {"interfaces": ["eth0"], "subnets": plan_to_dhcp(PLAN)["subnets"]}}
LEASES = [{"ip": "10.1.20.120", "mac": "aa:bb:cc:00:00:20", "hostname": "phone", "state": "active",
           "expires": "2026-10-13T10:00"},
          {"ip": "10.1.20.121", "mac": "", "hostname": "", "state": "declined", "expires": "2026-10-13T10:00"}]
SEEN = {"10.1.20.1": {"ping": True, "mac": "aa:bb:cc:00:00:99"},           # the gateway
        "10.1.20.10": {"ping": True, "mac": "aa:bb:cc:00:00:10"},          # nas, recorded
        "10.1.20.150": {"ping": True, "mac": "aa:bb:cc:00:00:77"},         # cam1's address, another MAC answering
        "10.1.20.120": {"ping": True, "mac": "aa:bb:cc:00:00:20"},         # a lease
        "10.1.20.121": {"ping": True, "mac": "aa:bb:cc:00:00:21"},         # Kea's ping-check declined it
        "10.1.20.55": {"ping": True, "mac": "aa:bb:cc:00:00:55"},          # set by hand, nobody recorded it
        "10.1.20.56": {"ping": False, "mac": "aa:bb:cc:00:00:56"},         # drops pings, answers ARP
        "10.1.20.57": {"ping": True, "mac": ""}}                           # ping only (no ARP entry)
AUDIT, PROBED = [], []
m_scan.write_audit = lambda actor, action, detail, source="cli", path=None: AUDIT.append((actor, action, detail,
                                                                                         source))
m_scan.load_plan_cache = lambda: PLAN
ALLOW = {"site": "home", "allowed": True, "policy": "allow", "source": "default", "why": "", "stale": "",
         "org": {"policy": "", "enforced": False}, "site_level": {"policy": ""}}


def probe(cidr, container):
    PROBED.append((cidr, container))
    return dict(SEEN)


def scan(subnet, state=None, **kw):
    kw.setdefault("policy", lambda v: ALLOW)
    return m_scan.scan_subnet(V, "alice", subnet, source="web", container="kt-kea", state_dir=state or
                              os.path.join(TMP, f"state-{len(PROBED)}-{len(AUDIT)}"), probe=probe,
                              leases=LEASES, **kw)


# ---- which subnets: every subnet of this site's plan, DHCP on or off (2.1.10.28)
# covers: agent:get.ipam.scan +
listed = scannable_subnets(V, cache=lambda: PLAN)
check("the subnets a scan may cover: every subnet of the plan, DHCP off too, a /22 at most (the /21 left out)",
      [(s["cidr"], s["dhcp"]) for s in listed] == [("10.1.20.0/24", True), ("10.1.40.0/24", False)]
      and listed[0]["hosts"] == 254, listed)
check("another site's kept plan adds nothing", [s["cidr"] for s in scannable_subnets(
    V, cache=lambda: {**PLAN, "site": "lab"})] == ["10.1.20.0/24"])
check("with Kea not installed nothing may be scanned (the scan runs in its container)",
      scannable_subnets({**V, "install_kea": False}, cache=lambda: PLAN) == [])
# covers: cli:ipam.scan agent:post.ipam.scan +
res = scan("10.1.20.0/24")
by = {f["ip"]: f for f in res["answering"]}
check("a served subnet is scanned by its exact network, in Kea's container", PROBED[-1] == ("10.1.20.0/24", "kt-kea")
      and res["subnet"] == {"name": "iot", "cidr": "10.1.20.0/24"} and res["scanned"] == 254, (PROBED, res))
check("what answered is set beside the plan: the gateway and a static address recorded, a lease a lease",
      by["10.1.20.1"]["status"] == "recorded" and by["10.1.20.1"]["kind"] == "gateway"
      and by["10.1.20.10"]["status"] == "recorded" and by["10.1.20.10"]["name"] == "nas"
      and by["10.1.20.120"]["status"] == "lease" and by["10.1.20.120"]["name"] == "phone", res)
check("an address set by hand that nobody recorded: in use, unrecorded, with the MAC ARP saw",
      by["10.1.20.55"]["status"] == "unrecorded" and by["10.1.20.55"]["mac"] == "aa:bb:cc:00:00:55"
      and by["10.1.20.55"]["how"] == "ping+arp", by["10.1.20.55"])
check("a device that drops pings is found by ARP; one ARP did not see has no MAC",
      by["10.1.20.56"]["how"] == "arp" and by["10.1.20.56"]["status"] == "unrecorded"
      and by["10.1.20.57"]["how"] == "ping" and by["10.1.20.57"]["mac"] == "", (by["10.1.20.56"], by["10.1.20.57"]))
check("an address Kea's ping-check declined is in use but unrecorded, saying why",
      by["10.1.20.121"]["status"] == "unrecorded" and "declined" in by["10.1.20.121"]["note"], by["10.1.20.121"])
check("a reservation answering from another MAC is recorded, with a note naming both MACs",
      by["10.1.20.150"]["status"] == "recorded" and "aa:bb:cc:00:00:77" in by["10.1.20.150"]["note"]
      and "aa:bb:cc:00:00:01" in by["10.1.20.150"]["note"], by["10.1.20.150"])
check("the count of unrecorded addresses, and the scan audited (who, which subnet, how many) from its source",
      res["unrecorded"] == 4 and AUDIT[-1][:2] == ("alice", "IPAM_SCAN") and "subnet=10.1.20.0/24" in AUDIT[-1][2]
      and "unrecorded=4" in AUDIT[-1][2] and AUDIT[-1][3] == "web", (res["unrecorded"], AUDIT[-1:]))
check("a scan by the subnet's name is the same scan", scan("iot")["subnet"]["cidr"] == "10.1.20.0/24")
lab = scan("lab")
check("a subnet DHCP does not serve is scanned too (2.1.10.28): its static address recorded, the rest unrecorded",
      lab["subnet"] == {"name": "lab", "cidr": "10.1.40.0/24"} and PROBED[-1] == ("10.1.40.0/24", "kt-kea")
      and lab["policy"]["source"] == "default", lab)
OLD = {**V, "dhcp": {"interfaces": ["eth0"], "subnets": [{"subnet": "10.1.20.0/24", "name": "iot",
                                                          "routers": "10.1.20.1",
                                                          "reservations": [{"mac": "aa:bb:cc:00:00:55",
                                                                            "ip": "10.1.20.55"}]}]}}
m_scan.load_plan_cache = lambda: None
old = m_scan.scan_subnet(OLD, "root", "iot", state_dir=os.path.join(TMP, "old"), probe=probe, leases=[],
                         policy=lambda v: ALLOW)
m_scan.load_plan_cache = lambda: PLAN
check("a site not yet upgraded: its reservations and router in the settings count as recorded",
      {f["ip"]: f["status"] for f in old["answering"]}.get("10.1.20.55") == "recorded"
      and {f["ip"]: f["kind"] for f in old["answering"]}.get("10.1.20.1") == "gateway", old["answering"])

# ---- refusals: nothing probed, nothing audited
# covers: cli:ipam.scan agent:post.ipam.scan -
before = (len(PROBED), len(AUDIT))
for typed, words in (("10.9.9.0/24", "not a subnet of this site's plan"), ("nosuch", "not a subnet of this site's"),
                     ("10.1.20.5/24", "host bits zero"), ("10.1.20.0/33", "not a network"), ("", "name the subnet"),
                     ("10.1.20.0/25", "not a subnet of this site's"), ("10.1.32.0/21", "larger than a /22")):
    check(f"refused: a scan of {typed!r}, saying why", refused(lambda: scan(typed), words) is True,
          refused(lambda: scan(typed), words))
check("refused: a scan at a site without Kea (its container runs the scan)", refused(
    lambda: m_scan.scan_subnet({**V, "install_kea": False}, "a", "iot", probe=probe, policy=lambda v: ALLOW),
    "DHCP is off at this site") is True)
check("nothing was probed or audited for a refused scan", (len(PROBED), len(AUDIT)) == before, (PROBED, AUDIT))
state = os.path.join(TMP, "cool")
scan("iot", state)
check("refused: the same subnet again within a minute (how long to wait), unprobed",
      refused(lambda: scan("iot", state), "scanned 0 s ago") is True and len(PROBED) == before[0] + 1,
      refused(lambda: scan("iot", state), "scanned"))
held = os.path.join(TMP, "held")
os.makedirs(held)
fd = os.open(os.path.join(held, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
check("refused: a second scan while one runs (one at a time on the host)",
      refused(lambda: scan("iot", held), "another scan is running") is True)
os.close(fd)
check("the lock and the times are root's alone (0700)", oct(os.stat(state).st_mode & 0o777) == "0o700")

# ---- the probe: fixed argument lists inside Kea's container, never a shell
CALLS = []


class Done:
    def __init__(self, out, code=0, err=""):
        self.stdout, self.returncode, self.stderr = out, code, err


ARP = ("IP address       HW type     Flags       HW address            Mask     Device\n"
       "10.1.20.55       0x1         0x2         aa:bb:cc:00:00:55     *        eth0\n"
       "10.1.20.60       0x1         0x0         00:00:00:00:00:00     *        eth0\n"
       "10.1.21.9        0x1         0x2         aa:bb:cc:00:00:09     *        eth0\n")


def fake_run(argv, **kw):
    CALLS.append((argv, kw))
    return Done("10.1.20.1\n10.1.20.55\n" if "fping" in argv else ARP, 1 if "fping" in argv else 0)


real_run = m_probe.subprocess.run
m_probe.subprocess.run = fake_run
got = m_probe.probe_subnet("10.1.20.0/24", "kt-kea")
check("the probe runs fping then reads the neighbour table in Kea's container, each a fixed argument list (no shell)",
      [c[0] for c in CALLS] == [["docker", "exec", "kt-kea", "fping", "-a", "-r", "1", "-t", "500", "-i", "10", "-g",
                                 "10.1.20.0/24"], ["docker", "exec", "kt-kea", "cat", "/proc/net/arp"]]
      and all("shell" not in c[1] for c in CALLS), CALLS)
check("rate-limited: one probe every 10 ms, one retry, 500 ms to answer", m_probe.FPING[m_probe.FPING.index("-i") + 1]
      == "10" and m_probe.FPING[m_probe.FPING.index("-r") + 1] == "1")
check("what answered: ping, ARP's complete entries inside the subnet only (an incomplete entry and another network's "
      "left out)", got == {"10.1.20.1": {"ping": True, "mac": ""}, "10.1.20.55": {"ping": True,
                                                                                  "mac": "aa:bb:cc:00:00:55"}}, got)
m_probe.subprocess.run = lambda argv, **kw: Done("", 1, "OCI runtime exec failed: exec: \"fping\": executable file "
                                                         "not found in $PATH")
check("refused, loudly: Kea's image without fping (older than 0.8.0), naming the fix",
      refused(lambda: m_probe.probe_subnet("10.1.20.0/24"), "update Kea's image") is True)
m_probe.subprocess.run = lambda argv, **kw: Done("", 1, "Error response from daemon: No such container: kea-dhcp4")
check("refused, loudly: Kea's container not running", refused(lambda: m_probe.probe_subnet("10.1.20.0/24"),
                                                             "is not running") is True)


def slow(argv, **kw):
    raise subprocess.TimeoutExpired(argv, 120)


m_probe.subprocess.run = slow
check("refused, loudly: a scan that does not finish in time", refused(lambda: m_probe.probe_subnet("10.1.20.0/24"),
                                                                       "did not finish") is True)
m_probe.subprocess.run = real_run

# ---- what is shown, and the offer to record
text = show_scan(res)
check("the result as text: every address, the unrecorded marked, the command that would reserve each",
      "IN USE, UNRECORDED" in text and "4 in use but unrecorded" in text
      and "ipam address add 10.1.20.55 --kind reservation --mac aa:bb:cc:00:00:55" in text
      and "ipam address add 10.1.20.57 --kind static" in text, text)
ADDED = []


def fake_add(v, actor, ip, kind, site="", name="", mac="", owner="", notes="", dns=False, vid=None, **kw):
    if ip == "10.1.20.121":
        raise ValidationError("10.1.20.121 is in a dhcp range: only a reservation goes there")
    ADDED.append((ip, kind, name, mac, notes))
    return {"result": {"ip": ip, "kind": kind}, "warnings": [], "done": [], "site": "home"}


m_offer.add_address = fake_add
answers = {"10.1.20.55": True, "10.1.20.56": False, "10.1.20.57": True, "10.1.20.121": True}
asked = []


def yes_no(qid, question, now):
    asked.append((qid, question, now))
    return answers[question.split()[1]]


out = io.StringIO()
with redirect_stdout(out):
    # covers: ask:ipam.scan_record ask:ipam.scan_name +
    # covers: ask:ipam.scan_record -
    done = m_offer.offer_reservations(V, res, ask=lambda qid, prompt, default: "cam4",
                                      ask_yes_no=yes_no)
check("asked for each address in use but unrecorded, no by default; only those were offered",
      sorted(q[1].split()[1] for q in asked) == ["10.1.20.121", "10.1.20.55", "10.1.20.56", "10.1.20.57"]
      and all(q[0] == "ipam.scan_record" and q[2] is False for q in asked), asked)
check("yes with a MAC: made a reservation for that MAC through the reservation unit, noted as found by a scan",
      ("10.1.20.55", "reservation", "cam4", "aa:bb:cc:00:00:55") in [a[:4] for a in ADDED]
      and all("found by a scan" in a[4] for a in ADDED), ADDED)
check("yes without a MAC: recorded as a static address; no: left alone",
      ("10.1.20.57", "static", "cam4", "") in [a[:4] for a in ADDED] and not any(a[0] == "10.1.20.56" for a in ADDED),
      ADDED)
# covers: ask:ipam.scan_name -
check("a find the plan's rules refuse is said, not recorded, and the next is still asked",
      "not recorded: 10.1.20.121 is in a dhcp range" in out.getvalue() and len(done) == 2, out.getvalue())


# ---- `fabricctl ipam scan`
def cli(*argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e):
        code = m_cmd.run_ipam_command(V, list(argv))
    return code, o.getvalue(), e.getvalue()


m_cmd.scan_subnet = lambda v, actor, subnet: scan(subnet)
code, o, e = cli("scan", "iot", "--no-ask")
check("fabricctl ipam scan: the result, nothing asked with --no-ask (exit 0)", code == 0 and "scanned 10.1.20.0/24 "
      "(iot)" in o and "IN USE, UNRECORDED" in o, (code, o, e))
m_cmd.scan_subnet = m_scan.scan_subnet
code, o, e = cli("scan", "10.9.9.0/24")
check("fabricctl ipam scan of a subnet not in the plan: refused, saying why (exit 1)",
      code == 1 and "not a subnet of this site's plan" in e, (code, e))
code, o, e = cli("scan", "iot", "--site", "lab")
check("fabricctl ipam scan of another site: refused (a scan covers this site's own subnets)",
      code == 1 and "only this site's own subnets" in e, (code, e))
code, o, e = cli("scan")
check("fabricctl ipam scan without a subnet: the usage (exit 2)", code == 2 and "ipam scan <subnet>" in e, code)
check("the usage lists scan", "fabricctl ipam scan <subnet> [--no-ask]" in m_cmd.USAGE)

# ---- the agent: the permission each route needs, and the record route's refusals
check("permissions: the scan and recording a find need dhcp:write; listing what may be scanned dhcp:read",
      required_permission("POST", ["ipam", "scan"]) == "dhcp:write"
      and required_permission("POST", ["ipam", "scan", "record"]) == "dhcp:write"
      and required_permission("GET", ["ipam", "scan"]) == "dhcp:read")
# covers: agent:get.ipam.scan agent:post.ipam.scan.record -
check("refused: a user without dhcp:write (the auditor) may list the subnets but not scan or record",
      "dhcp:read" in BUNDLES["fabric-auditor"] and "dhcp:write" not in BUNDLES["fabric-auditor"]
      and "dhcp:write" in BUNDLES["fabric-network-operator"]
      and required_permission("POST", ["ipam", "scan", "anything"]) is None)
sys.path.insert(0, os.path.join(REPO, "src"))
try:
    import agent.post_ipam_scan as m_agent  # noqa: E402
    from agent.route_not_found import RouteNotFound  # noqa: E402
    agent_ok = True
except ImportError as exc:          # the agent's imports need the host's modules (yaml, ...)
    agent_ok, why = False, exc
if agent_ok:
    m_agent.load_vars = lambda: V
    m_agent.add_address = fake_add
    m_agent.apply_changes = lambda actor, source: (True, "applied")
    m_agent.refresh_firewall = lambda: (True, "in line")
    check("refused: recording a find as anything but a reservation or a static address",
          refused(lambda: m_agent.post_ipam_scan(["ipam", "scan", "record"], "alice",
                                                 {"ip": "10.1.20.55", "kind": "infrastructure"}),
                  "reservation or a static") is True)
    check("refused: a field that is not text (400)", refused(lambda: m_agent.post_ipam_scan(
        ["ipam", "scan", "record"], "alice", {"ip": ["10.1.20.55"]}), "must be text") is True)
    try:
        m_agent.post_ipam_scan(["ipam", "scan", "other"], "alice", {})
        nf = False
    except RouteNotFound:
        nf = True
    check("another route under ipam/scan: not found (404)", nf)
    # covers: agent:post.ipam.scan.record +
    rec = m_agent.post_ipam_scan(["ipam", "scan", "record"], "alice", {"ip": "10.1.20.55", "kind": "reservation",
                                                                       "mac": "aa:bb:cc:00:00:55", "name": "cam4"})
    check("a find recorded from the console: the reservation unit, then applied", rec["applied"] is True
          and rec["address"] == {"ip": "10.1.20.55", "kind": "reservation"} and ADDED[-1][:4] == (
              "10.1.20.55", "reservation", "cam4", "aa:bb:cc:00:00:55"), rec)
else:
    check("the agent's scan routes import", False, why)

# ---- the console's scan page
sys.path.insert(0, REPO)
try:
    from webui import agentclient as actions  # noqa: E402
    import webui.routes.networks_scan_post as m_post  # noqa: E402
    import webui.routes.networks_scan_page as m_page  # noqa: E402
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
    CTX = {"user": "alice", "csrf": "tok", "perms": ["dhcp:read", "dhcp:write"], "version": "0.8.0"}
    m_post.page_context = lambda sess: CTX
    actions.scannable_subnets = lambda: {"subnets": listed, "policy": ALLOW, "policy_error": ""}
    actions.scan_subnet = lambda subnet: res
    h = H()
    # covers: web:get.networks.scan +
    m_page.networks_scan_page(h, CTX, {})
    check("the scan page lists every subnet of the plan (DHCP off marked), the policy and its source, and the button",
          h.sent[0] == 200 and "10.1.20.0/24 — iot" in h.sent[1] and "10.1.40.0/24 — lab (VLAN 40) · DHCP off"
          in h.sent[1] and "Scan now" in h.sent[1] and "allowed" in h.sent[1] and "(default;" in h.sent[1], h.sent)
    h = H()
    # covers: web:post.networks.scan +
    m_post.networks_scan_post(h, {}, [], {"subnet": "10.1.20.0/24", "csrf": "tok"})
    check("after a scan: each find in use but unrecorded offered as a reservation with the MAC ARP saw, or static",
          h.sent[0] == 200 and "In use, unrecorded" in h.sent[1] and "Make it a reservation?" in h.sent[1]
          and 'value="aa:bb:cc:00:00:55"' in h.sent[1] and "Record it as a static address?" in h.sent[1]
          and 'action="/networks/scan/record"' in h.sent[1], h.sent[1][-600:] if h.sent else h.sent)
    page = h.sent[1]
    h = H()
    # covers: web:get.networks.scan -
    m_page.networks_scan_page(h, {**CTX, "perms": ["dhcp:read"]}, {})
    check("a user without dhcp:write sees the subnets but no scan button, saying which permission it needs",
          "Scan now" not in h.sent[1] and "dhcp:write" in h.sent[1], h.sent[1][-400:])

    def no(subnet):
        raise actions.ValidationError("10.9.9.0/24 is not a subnet this site's DHCP serves")
    actions.scan_subnet = no
    h = H()
    # covers: web:post.networks.scan -
    m_post.networks_scan_post(h, {}, [], {"subnet": "10.9.9.0/24"})
    check("a scan the agent refuses goes back to the page saying why", h.to and h.to.startswith("/networks/scan?err=")
          and "serves" in h.to, h.to)
    actions.record_found_address = lambda ip, kind, mac, name: {"address": {"ip": ip, "kind": kind, "mac": mac},
                                                                "warnings": [], "applied": True, "output": ""}
    h = H()
    # covers: web:post.networks.scan.record +
    m_post.networks_scan_post(h, {}, ["record"], {"ip": "10.1.20.55", "kind": "reservation",
                                                  "mac": "aa:bb:cc:00:00:55", "name": "cam4"})
    check("make it a reservation: recorded, back to the scan page saying so", h.to and "msg=Reserved+10.1.20.55" in h.to,
          h.to)

    def bad_record(ip, kind, mac, name):
        raise actions.ValidationError("10.1.20.55 is already cam1's")
    actions.record_found_address = bad_record
    h = H()
    # covers: web:post.networks.scan.record -
    m_post.networks_scan_post(h, {}, ["record"], {"ip": "10.1.20.55"})
    check("a find the plan refuses: back to the scan page saying why", h.to and "err=" in h.to, h.to)
    h = H()
    m_post.networks_scan_post(h, {}, ["other"], {})
    check("another path under /networks/scan: 404", h.sent == (404, "Not found."), h.sent)
    check("the page has no inline script or style (the strict CSP)", "<script" not in page and "style=" not in page)
else:
    print(f"SKIP the console's scan page: {why}")

# ---- ping-check: the setting and the Kea template
# covers: setting:dhcp +
env = jinja_env(os.path.join(REPO, "templates"))
KV = {"install_kea": True, "domain": "lan.test", "host_ip": "10.1.0.2", "ip_kea_ddns": "10.255.0.97",
      "deploy_base_dir": "/opt", "dhcp": {"interfaces": ["eth0"], "subnets": [{"subnet": "10.1.20.0/24",
                                                                               "pools": ["10.1.20.100 - 10.1.20.200"]}]}}
on = env.get_template("kea/kea-dhcp4.conf.j2").render(**{**KV, "dhcp": normalize_dhcp(KV)})
check("ping-check on by default: Kea's ping_check hook with its global parameters (one ping, 100 ms)",
      '"library": "libdhcp_ping_check.so"' in on and '"enable-ping-check": true' in on
      and '"reply-timeout": 100' in on, on[:900])
KV_OFF = {**KV, "dhcp": {**KV["dhcp"], "ping_check": False}}
off = env.get_template("kea/kea-dhcp4.conf.j2").render(**{**KV_OFF, "dhcp": normalize_dhcp(KV_OFF)})
check("dhcp.ping_check: false leaves the hook out", "ping_check" not in off and "libdhcp_lease_cmds.so" in off)
# covers: setting:dhcp -
check("refused: dhcp.ping_check that is not true or false",
      refused(lambda: normalize_dhcp({**KV, "dhcp": {**KV["dhcp"], "ping_check": "yes"}}), "dhcp.ping_check") is True)
compose = open(os.path.join(REPO, "templates", "kea", "docker-compose.yml.j2")).read()
check("least privilege: Kea's container keeps exactly its two capabilities (the scan adds none)",
      compose.count("cap_add:") == 1 and "- NET_RAW\n      - NET_BIND_SERVICE\n    tmpfs" in compose)
dockerfile = open(os.path.join(REPO, "packaging", "images", "kea", "Dockerfile")).read()
check("Kea's image carries fping for the scan", " fping " in dockerfile.split("tini", 1)[1][:10] or "tini fping"
      in dockerfile)

shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
