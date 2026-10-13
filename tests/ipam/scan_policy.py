#!/usr/bin/env python3
"""The `ipam` suite, the scan policy with no container (manual 1.10.4.27, decision 2.1.10.28): the effective policy as a
group policy's enforcement works (the organisation's level enforced wins; else the site's own; else the
organisation's; else allow), the refusal naming the level that denied; the policy read from the DC, or this site's kept
copy, or refused; a denied scan probing and auditing nothing; a level checked and written through the plan's edit;
`fabricctl ipam scan-policy`; the agent's routes and their permissions; the console's forms on the Networks tab and the
scan page. The policy at a real DC: tests/samba/ipam.py.

    python3 tests/ipam/scan_policy.py
"""
import io
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.ipam.run_ipam_command as m_cmd  # noqa: E402
import fabriclib.ipam.scan_subnet as m_scan  # noqa: E402
import fabriclib.ipam.scanpolicy.run_scan_policy_command as m_run  # noqa: E402
import fabriclib.ipam.scanpolicy.set_scan_policy as m_set  # noqa: E402
from fabriclib.ipam.scanpolicy.effective_scan_policy import effective_scan_policy  # noqa: E402
from fabriclib.ipam.scanpolicy.read_scan_policy import read_scan_policy  # noqa: E402
from fabriclib.ipam.scanpolicy.show_scan_policy import show_scan_policy  # noqa: E402
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

FAILED = 0
TMP = tempfile.mkdtemp(prefix="fabric-scanpolicy-test-")


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


def levels(org="", enforced=False, site=None, name="lab"):
    out = {"org": {"policy": org, "enforced": enforced}}
    if site is not None:
        out[name] = {"policy": site, "enforced": False}
    return out


# ---- the effective policy (1.10.4.27.3)
p = effective_scan_policy({}, "lab")
check("default: nothing set anywhere, scans allowed (source default)", p["allowed"] and p["source"] == "default"
      and p["why"] == "", p)
p = effective_scan_policy(levels(org="deny"), "lab")
check("the organisation denies, not enforced, the site unset: denied by the organisation, the site may allow itself",
      not p["allowed"] and p["source"] == "organisation" and "site's own level may allow it" in p["why"], p)
p = effective_scan_policy(levels(org="deny", site="allow"), "lab")
check("the organisation denies, not enforced, the site allows: the site's own setting wins", p["allowed"]
      and p["source"] == "site lab", p)
p = effective_scan_policy(levels(org="deny", enforced=True, site="allow"), "lab")
check("the organisation denies, ENFORCED, the site allows: denied, saying the enforced organisation's level did it",
      not p["allowed"] and p["source"] == "organisation (enforced)" and "(enforced)" in p["why"]
      and "only the organisation's level can allow it" in p["why"] and "at lab" in p["why"], p)
p = effective_scan_policy(levels(org="allow", enforced=True, site="deny"), "lab")
check("the organisation allows, enforced, the site denies: allowed (enforcement wins both ways)", p["allowed"]
      and p["source"] == "organisation (enforced)", p)
p = effective_scan_policy(levels(org="allow", site="deny"), "lab")
check("the site denies itself, the organisation allows unenforced: denied by the site's own policy, naming the fix",
      not p["allowed"] and p["source"] == "site lab" and "by its own scan policy" in p["why"]
      and "set site allow" in p["why"], p)
p = effective_scan_policy(levels(enforced=True, site="deny"), "lab")
check("enforced with no value: allow is enforced", p["allowed"] and p["source"] == "organisation (enforced)", p)
p = effective_scan_policy(levels(site="sometimes"), "lab")
check("a value fabric never writes counts as deny (fails closed)", not p["allowed"], p)
p = effective_scan_policy(levels(org="deny", site="allow", name="home"), "lab")
check("another site's level does not count for this one", not p["allowed"] and p["source"] == "organisation", p)
check("the levels shown as they are", effective_scan_policy(levels(org="deny", enforced=True, site=""), "lab")["org"]
      == {"policy": "deny", "enforced": True})
text = show_scan_policy({**effective_scan_policy(levels(org="deny", enforced=True, site="allow"), "lab"),
                         "stale": "the domain did not answer"})
check("shown as text: denied, the source, both levels, why, the stale note",
      "scan policy at lab: denied (organisation (enforced))" in text and "organisation: deny, enforced" in text
      and "site lab: allow" in text and "note: the domain did not answer" in text, text)

# ---- reading it (1.10.4.27.4)
V = {"site_name": "home", "install_kea": True}


def dc(levels_):
    return lambda v, secrets, of="", container="samba": {"scan_policy": levels_}


def down(v, secrets, of="", container="samba"):
    raise ValidationError("the DC did not answer")


got = read_scan_policy(V, read=dc(levels(org="deny", site="allow", name="home")), cache=lambda: None)
check("read from the DC as this site's agent: the site's allow over the organisation's deny", got["allowed"]
      and got["source"] == "site home" and got["stale"] == "", got)
got = read_scan_policy(V, read=down, cache=lambda: {"site": "home", "read": "2026-10-13 09:00:00",
                                                     "scan_policy": levels(org="deny", enforced=True)})
check("the DC not answering: this site's kept copy, saying so and when it was read", not got["allowed"]
      and "did not answer" in got["stale"] and "2026-10-13 09:00:00" in got["stale"], got)
check("refused: the DC not answering and no kept copy (no scan against a policy nobody could read)",
      refused(lambda: read_scan_policy(V, read=down, cache=lambda: None), "the scan policy cannot be read") is True)
check("refused: a kept copy from before the policy existed counts as none",
      refused(lambda: read_scan_policy(V, read=down, cache=lambda: {"site": "home"}), "cannot be read") is True)
check("refused: another site's policy while the DC does not answer (only this site's is kept)",
      refused(lambda: read_scan_policy(V, "lab", read=down, cache=lambda: {"scan_policy": {}}), "cannot be read")
      is True)

# ---- a scan the policy denies: nothing probed, nothing audited
PLAN = {"site": "home", "block": 1, "vlans": [{"id": 20, "name": "iot", "access": "full"}],
        "subnets": [{"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "gateway": "10.1.20.1", "dhcp": True, "id": 1,
                     "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "dhcp", "first": "10.1.20.100", "last": "10.1.20.249"}], "addresses": []}]}
VS = {**V, "dhcp": {"interfaces": ["eth0"], "subnets": plan_to_dhcp(PLAN)["subnets"]}}
PROBED, AUDIT = [], []
m_scan.write_audit = lambda actor, action, detail, source="cli", path=None: AUDIT.append((actor, action, detail))


def probe(cidr, container):
    PROBED.append(cidr)
    return {"10.1.20.1": {"ping": True, "mac": ""}}


def scan(policy):
    return m_scan.scan_subnet(VS, "alice", "iot", container="kt", state_dir=os.path.join(TMP, f"s{len(AUDIT)}"),
                              probe=probe, leases=[], policy=lambda v: effective_scan_policy(policy, "home"),
                              cache=lambda: PLAN)


# covers: cli:ipam.scan agent:post.ipam.scan -
why = refused(lambda: scan(levels(org="deny", enforced=True, site="allow", name="home")), "by the organisation's "
              "scan policy (enforced)")
check("refused: a scan the enforced organisation's level denies, though the site allows, naming that level",
      why is True and not PROBED and not AUDIT, (why, PROBED, AUDIT))
why = refused(lambda: scan(levels(site="deny", name="home")), "by its own scan policy")
check("refused: a scan the site's own level denies, naming it; nothing probed or audited",
      why is True and not PROBED and not AUDIT, (why, PROBED, AUDIT))
# covers: cli:ipam.scan agent:post.ipam.scan +
res = scan({})
check("allowed by default: the scan runs, and its result says which level allowed it", PROBED == ["10.1.20.0/24"]
      and res["policy"]["source"] == "default" and AUDIT[-1][1] == "IPAM_SCAN", (PROBED, res.get("policy")))

# ---- setting a level (1.10.4.27.5)
EDITS = []


def fake_edit(v, actor, site, event, change, secrets=None, container="samba", source="cli"):
    plan = {"scan_policy": levels(org="deny", enforced=True)}
    changes, result, detail, warnings = change(plan)
    EDITS.append((actor, site, event, changes, detail, source))
    return {"result": result, "warnings": warnings, "done": ["set"], "site": site or v["site_name"]}


m_set.edit_options = fake_edit
out = m_set.set_scan_policy(V, "alice", "org", "deny", True)
check("the organisation's level: deny, enforced, written as one scan_policy change on the organisation's set, audited",
      EDITS[-1][3] == [{"do": "set", "what": "scan_policy", "site": "home", "key": "org",
                        "fields": {"policy": "deny", "enforced": True}}]
      and EDITS[-1][2] == "IPAM_SCAN_POLICY_SET" and "level=org" in EDITS[-1][4] and "enforced=True" in EDITS[-1][4]
      and out["result"]["enforced"] is True, EDITS[-1])
out = m_set.set_scan_policy(V, "alice", "org", "allow")
check("the organisation's level without --enforced keeps the enforcement as it is (not written, shown as before)",
      EDITS[-1][3][0]["fields"] == {"policy": "allow"} and out["result"]["enforced"] is True, (EDITS[-1], out))
out = m_set.set_scan_policy(V, "alice", "site", "inherit", site="lab", source="web")
check("a site's level: inherit clears its value; the site's plan is the one edited; from the console",
      EDITS[-1][1] == "lab" and EDITS[-1][3][0]["key"] == "lab" and EDITS[-1][3][0]["fields"] == {"policy": ""}
      and out["result"]["policy"] == "inherit" and EDITS[-1][5] == "web", EDITS[-1])
out = m_set.set_scan_policy(V, "alice", "site", "deny")
check("a site's level: this site by default", EDITS[-1][3][0]["key"] == "home"
      and EDITS[-1][3][0]["fields"] == {"policy": "deny"}, EDITS[-1])
before = len(EDITS)
for args, words in ((("org", "inherit"), "the organisation's scan policy is allow or deny"),
                    (("site", "maybe"), "a site's scan policy is allow, deny or inherit"),
                    (("forest", "deny"), "level is org or site")):
    check(f"refused: {args}, saying why", refused(lambda: m_set.set_scan_policy(V, "a", *args), words) is True)
check("refused: --enforced on a site's level", refused(lambda: m_set.set_scan_policy(V, "a", "site", "deny", True),
                                                       "--enforced is the organisation's") is True)
check("refused: --site with the organisation's level", refused(
    lambda: m_set.set_scan_policy(V, "a", "org", "deny", None, "lab"), "one value for every site") is True)
check("a refused level writes nothing", len(EDITS) == before)


# ---- `fabricctl ipam scan-policy`
def cli(*argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e):
        code = m_cmd.run_ipam_command(V, list(argv))
    return code, o.getvalue(), e.getvalue()


SHOWN = []
m_run.read_scan_policy = lambda v, site="", secrets=None, container="samba": (
    SHOWN.append(site) or {**effective_scan_policy(levels(org="deny", enforced=True), site or "home"), "stale": ""})
# covers: cli:ipam.scan-policy +
code, o, e = cli("scan-policy")
check("scan-policy: the policy here, its source and both levels (exit 0)", code == 0
      and "scan policy at home: denied (organisation (enforced))" in o and "organisation: deny, enforced" in o, (o, e))
code, o, e = cli("scan-policy", "show", "--site", "lab")
check("scan-policy show --site: a site below", code == 0 and "scan policy at lab" in o and SHOWN[-1] == "lab", o)
code, o, e = cli("scan-policy", "set", "org", "deny", "--enforced", "on")
check("scan-policy set org deny --enforced on: set, then shown", code == 0
      and "the organisation's scan policy is deny, enforced" in o and EDITS[-1][3][0]["fields"]["enforced"] is True,
      (o, e))
code, o, e = cli("scan-policy", "set", "site", "allow", "--site", "lab")
check("scan-policy set site allow --site lab", code == 0 and "lab's scan policy is allow" in o
      and EDITS[-1][3][0]["key"] == "lab", (o, e))
# covers: cli:ipam.scan-policy -
for argv, words, want in ((("scan-policy", "set", "org", "deny", "--enforced", "maybe"), "--enforced is on or off", 1),
                          (("scan-policy", "set", "org", "inherit"), "allow or deny", 1),
                          (("scan-policy", "set", "site", "deny", "--enforced", "on"), "--enforced is the", 1),
                          (("scan-policy", "--colour"), "unknown option --colour", 1),
                          (("scan-policy", "set", "org"), "fabricctl ipam scan-policy set org", 2)):
    code, o, e = cli(*argv)
    check(f"scan-policy {' '.join(argv[1:])}: refused (exit {want}), saying why", code == want and words in e,
          (code, e))
check("the usage lists scan-policy and sync", "fabricctl ipam scan-policy" in m_cmd.USAGE
      and "fabricctl ipam sync" in m_cmd.USAGE and "fabricctl ipam scan-policy set site" in m_run.USAGE)

# ---- the agent: permissions and routes
check("permissions: a site's level needs dhcp:write; the organisation's dhcp:org-options",
      required_permission("POST", ["ipam", "scan-policy"]) == "dhcp:write"
      and required_permission("POST", ["ipam", "scan-policy", "org"]) == "dhcp:org-options"
      and required_permission("POST", ["ipam", "scan-policy", "other"]) is None)
# covers: agent:post.ipam.scan-policy agent:post.ipam.scan-policy.org -
check("refused: the auditor may set neither level; a network operator a site's but not the organisation's",
      "dhcp:write" not in BUNDLES["fabric-auditor"] and "dhcp:org-options" not in BUNDLES["fabric-auditor"]
      and "dhcp:write" in BUNDLES["fabric-network-operator"]
      and "dhcp:org-options" not in BUNDLES["fabric-network-operator"])
sys.path.insert(0, os.path.join(REPO, "src"))
try:
    import agent.post_scan_policy as m_agent  # noqa: E402
    from agent.route_not_found import RouteNotFound  # noqa: E402
    agent_ok = True
except ImportError as exc:          # the agent's imports need the host's modules (yaml, ...)
    agent_ok, why = False, exc
if agent_ok:
    CALLS = []
    m_agent.load_vars = lambda: V

    def fake_set(v, actor, level, value, enforced=None, site="", secrets=None, container="samba", source="cli"):
        CALLS.append((actor, level, value, enforced, site, source))
        return {"result": {"level": level, "site": site or "org", "policy": value, "enforced": enforced}}

    def scope(v, site):
        if site == "evil":
            raise ValidationError("site 'evil' is not this site or one below it: this console shows home, lab")
        return site or "home"

    m_agent.set_scan_policy = fake_set
    m_agent.site_scope = scope
    # covers: agent:post.ipam.scan-policy +
    m_agent.post_scan_policy(["ipam", "scan-policy"], "alice", {"site": "lab", "policy": "deny"})
    check("POST /v1/ipam/scan-policy: a site's level, the site checked, from the web",
          CALLS[-1] == ("alice", "site", "deny", None, "lab", "web"), CALLS[-1:])
    # covers: agent:post.ipam.scan-policy.org +
    m_agent.post_scan_policy(["ipam", "scan-policy", "org"], "alice", {"policy": "deny", "enforced": "on"})
    check("POST /v1/ipam/scan-policy/org: the organisation's level, enforced on", CALLS[-1] == (
        "alice", "org", "deny", True, "", "web"), CALLS[-1:])
    m_agent.post_scan_policy(["ipam", "scan-policy", "org"], "alice", {"policy": "allow"})
    check("POST /v1/ipam/scan-policy/org without enforced keeps it", CALLS[-1][3] is None, CALLS[-1:])
    n = len(CALLS)
    # covers: agent:post.ipam.scan-policy -
    check("refused: a site this console does not show (400), nothing set", refused(lambda: m_agent.post_scan_policy(
        ["ipam", "scan-policy"], "alice", {"site": "evil", "policy": "deny"}), "not this site") is True
        and len(CALLS) == n)
    check("refused: a field that is not text", refused(lambda: m_agent.post_scan_policy(
        ["ipam", "scan-policy"], "alice", {"site": "lab", "policy": ["deny"]}), "must be text") is True)
    # covers: agent:post.ipam.scan-policy.org -
    check("refused: enforced that is neither on nor off", refused(lambda: m_agent.post_scan_policy(
        ["ipam", "scan-policy", "org"], "alice", {"policy": "deny", "enforced": "yes"}), "enforced is on or off")
        is True and len(CALLS) == n)
    try:
        m_agent.post_scan_policy(["ipam", "scan-policy", "org", "x"], "alice", {})
        nf = False
    except RouteNotFound:
        nf = True
    check("another route under ipam/scan-policy: not found (404)", nf)
else:
    check("the agent's scan-policy route imports", False, why)

# ---- the console: the Networks tab's card, the scan page, the forms
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
    READ = {"sites": [{"name": "home", "created": "1", "block": 1}], "plans": {"home": {k: PLAN[k] for k in (
        "vlans", "subnets")} | {"networks": []}}}
    SITES = [{"name": "home", "own": True}]
    CTX = {"user": "alice", "csrf": "tok", "perms": ["dhcp:read", "dhcp:write", "dhcp:org-options"],
           "version": "0.8.0"}

    def tab(policy, perms, editable=True):
        ov = networks_view(VS, READ, "home", SITES, [])
        ov.update(own="home", stale="", error="", leases_error="", sync=None,
                  scan_policy={**effective_scan_policy(policy, "home"), "org_editable": editable})
        return views.networks({**CTX, "perms": perms}, ov, "iot")

    page = tab(levels(org="deny", enforced=True, site="allow", name="home"), CTX["perms"])
    # covers: web:post.networks.scan.policy web:post.networks.scan.policy.org +
    check("the Networks tab's scan policy card: denied, by the enforced organisation's level, both levels, both forms",
          "Scan policy · home" in page and "denied" in page and "decided by organisation (enforced)" in page
          and 'action="/networks/scan/policy"' in page and 'action="/networks/scan/policy/org"' in page
          and "enforced: wins at every site" in page, page[:3000])
    check("a denied policy: no Scan this subnet link", "Scan this subnet" not in page)
    page = tab({}, CTX["perms"])
    check("allowed (the default): the subnet's Scan this subnet link", "Scan this subnet" in page
          and "decided by default" in page)
    # covers: web:post.networks.scan.policy web:post.networks.scan.policy.org -
    page = tab({}, ["dhcp:read"])
    check("without dhcp:write or dhcp:org-options: the card read-only, no form",
          "Scan policy · home" in page and "/networks/scan/policy" not in page, page[:2000])
    page = tab({}, ["dhcp:read", "dhcp:write", "dhcp:org-options"], editable=False)
    check("dhcp:org-options at a site the top has not let edit the organisation's settings: no organisation form, "
          "saying why", 'action="/networks/scan/policy/org"' not in page and 'action="/networks/scan/policy"' in page
          and "This site may not change the organisation's level" in page)
    denied = {**effective_scan_policy(levels(site="deny", name="home"), "home"), "stale": ""}
    page = views.ipam_scan(CTX, [{"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "dhcp": True, "hosts": 254}],
                           None, policy=denied)
    check("the scan page under a denying policy: why, which level, and no Scan button",
          "by its own scan policy" in page and "Scan now" not in page and "denied" in page, page[-1500:])
    page = views.ipam_scan(CTX, [{"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "dhcp": True, "hosts": 254}],
                           None, policy=None, policy_error="the scan policy cannot be read (DC down)")
    check("the scan page when the policy cannot be read: says so, no Scan button",
          "cannot be read" in page and "Scan now" not in page)
    SET = []

    def fake_policy(level, site, policy, enforced=""):
        SET.append((level, site, policy, enforced))
        if policy == "maybe":
            raise actions.ValidationError("a site's scan policy is allow, deny or inherit (got 'maybe')")
        return {"result": {"level": level, "site": site or "org", "policy": policy,
                           "enforced": (enforced == "on") if level == "org" and enforced else None}}

    actions.set_scan_policy = fake_policy
    h = H()
    m_post.networks_scan_post(h, {}, ["policy"], {"site": "lab", "policy": "deny", "csrf": "tok"})
    check("the site's form: set through the agent, back to the tab on that site saying what it is now",
          SET[-1] == ("site", "lab", "deny", "") and h.to.startswith("/networks?site=lab&msg=")
          and "lab%27s+scan+policy+is+deny" in h.to, h.to)
    h = H()
    m_post.networks_scan_post(h, {}, ["policy", "org"], {"site": "home", "policy": "deny", "enforced": "on"})
    check("the organisation's form: deny, enforced", SET[-1] == ("org", "home", "deny", "on")
          and "enforced" in h.to and "msg=" in h.to, h.to)
    h = H()
    m_post.networks_scan_post(h, {}, ["policy"], {"site": "lab", "policy": "maybe", "back": "scan"})
    check("a value the agent refuses: back to the scan page (where the form came from) saying why",
          h.to.startswith("/networks/scan?err=") and "inherit" in h.to, h.to)
else:
    print(f"SKIP the console's scan policy: {why}")

print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
