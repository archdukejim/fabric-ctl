#!/usr/bin/env python3
"""The `ipam` suite, the Networks tab's model (manual 1.10.4.21) with no container: a subnet drawn as a map (its
ranges as a bar, the counts, every address accounted for: the plan's, leases beside them, unrecorded leases, free
runs, a /16 in a handful of rows), the options with their sources and the "provided by fabric" marker, a level
another part of fabric adds appearing as soon as its data does, another site's view without this site's options, the
site scope (this site and the sites below it; any other refused), the agent's permission table for the new routes,
and the 0.7 subnet commands as aliases: their refusals that need no domain. The writes against a real DC:
tests/samba/ipam.py; the pages: tests/webui.

    python3 tests/ipam/networks.py
"""
import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.dhcp.run_dhcp_command as m_dhcp  # noqa: E402
import fabriclib.ipam.visible_sites as m_sites  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.ipam.common.fields import KEEP  # noqa: E402
from fabriclib.ipam.common.pool_text import pool_text  # noqa: E402
from fabriclib.ipam.common.site_scope import site_scope  # noqa: E402
from fabriclib.ipam.fabric_options import fabric_options  # noqa: E402
from fabriclib.ipam.networks_view import networks_view  # noqa: E402
from fabriclib.ipam.plan_rows import plan_rows  # noqa: E402
from fabriclib.ipam.remove_reservation_mac import remove_reservation_mac  # noqa: E402
from fabriclib.ipam.set_dhcp_subnet import set_dhcp_subnet  # noqa: E402
from fabriclib.ipam.subnet_map import subnet_map  # noqa: E402
from fabriclib.ipam.subnet_options import subnet_options  # noqa: E402
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


SPLIT = [{"kind": "gateway", "first": "10.1.20.1", "last": "10.1.20.1", "notes": ""},
         {"kind": "static", "first": "10.1.20.2", "last": "10.1.20.99", "notes": ""},
         {"kind": "dhcp", "first": "10.1.20.100", "last": "10.1.20.249", "notes": ""},
         {"kind": "reserved", "first": "10.1.20.250", "last": "10.1.20.254", "notes": ""}]
IOT = {"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "kind": "dhcp", "gateway": "10.1.20.1", "dhcp": True,
       "id": 2, "relay": "", "notes": "", "allow_overlap": "", "options": [{"name": "ntp-servers", "data": "10.1.10.3"}],
       "ranges": SPLIT,
       "addresses": [{"ip": "10.1.20.10", "kind": "static", "name": "nas", "mac": "", "owner": "office", "notes": "",
                      "dns": True, "options": []},
                     {"ip": "10.1.20.150", "kind": "reservation", "name": "cam1", "mac": "aa:bb:cc:dd:ee:01",
                      "owner": "", "notes": "", "dns": False, "options": [{"code": 67, "data": "cam.bin"}]}]}
BIG = {"name": "lab", "cidr": "10.9.0.0/16", "vlan": 90, "kind": "subnet", "gateway": "10.9.0.1", "dhcp": False,
       "id": 3, "relay": "", "notes": "", "allow_overlap": "", "options": [],
       "ranges": [{"kind": "dhcp", "first": "10.9.1.0", "last": "10.9.200.255", "notes": ""}], "addresses": []}
READ = {"sites": [{"name": "lan", "created": "1", "block": 1}, {"name": "parents", "created": "2", "block": None}],
        "plans": {"lan": {"vlans": [{"id": 20, "name": "iot", "purpose": "", "access": "full", "notes": ""},
                                    {"id": 90, "name": "lab", "purpose": "", "access": "full", "notes": ""}],
                          "subnets": [IOT, BIG], "networks": []},
                  "parents": {"vlans": [{"id": 20, "name": "iot", "purpose": "", "access": "full", "notes": ""}],
                              "subnets": [{**IOT, "cidr": "10.2.20.0/24", "gateway": "10.2.20.1", "ranges": [],
                                           "addresses": [], "options": []}], "networks": []}}}
LEASES = [{"ip": "10.1.20.120", "mac": "02:11:22:33:44:55", "hostname": "laptop1", "state": "active",
           "expires": "2026-10-13T08:00"},
          {"ip": "10.1.20.150", "mac": "aa:bb:cc:dd:ee:01", "hostname": "cam1", "state": "active",
           "expires": "2026-10-13T09:00"}]
V = {"site_name": "lan", "host_ip": "192.168.1.2", "domain": "home.arpa",
     "dhcp": {"options": [{"name": "time-offset", "data": "-18000"}]}}
SITES = [{"name": "lan", "own": True}, {"name": "parents", "own": False}]
PLAN = {"site": "lan", "block": 1, "vlans": READ["plans"]["lan"]["vlans"], "subnets": [IOT, BIG], "networks": []}

print("--- a subnet drawn as a map (1.10.4.21)")
rows = [r for r in plan_rows(PLAN, LEASES) if r["subnet"] == IOT["cidr"]]
m = subnet_map(IOT, rows)
kinds = [(r["ip"], r["kind"]) for r in m["rows"]]
check("every address accounted for: the gateway, the plan's two, the unrecorded lease, free runs between them",
      kinds[:4] == [("10.1.20.1", "gateway"), ("10.1.20.2", "free"), ("10.1.20.10", "static"),
                    ("10.1.20.11", "free")] and ("10.1.20.120", "lease") in kinds, kinds)
check("free runs add up with the used addresses to the whole subnet (254 hosts)",
      sum(r["count"] for r in m["rows"] if r["kind"] == "free") + m["counts"]["used"] == 254
      and m["counts"]["size"] == 254, m["counts"])
check("a free run never crosses a range: the static range's tail and the DHCP range's head are two rows",
      any(r["kind"] == "free" and r["ip"] == "10.1.20.11" and r["last"] == "10.1.20.99" for r in m["rows"])
      and any(r["kind"] == "free" and r["ip"] == "10.1.20.100" and r["last"] == "10.1.20.119" for r in m["rows"]))
check("a lease on a reservation sits beside it (its lease column), not as a row of its own",
      [r["kind"] for r in m["rows"] if r["ip"] == "10.1.20.150"] == ["reservation"]
      and next(r for r in m["rows"] if r["ip"] == "10.1.20.150")["lease"].startswith("active"))
check("a lease the plan does not hold is marked unrecorded and counted",
      next(r for r in m["rows"] if r["ip"] == "10.1.20.120")["unrecorded"] and m["counts"]["unrecorded"] == 1)
bar = m["bar"]
check("the bar: one segment per range, in order, spanning the whole width, with the used part of each",
      [b["kind"] for b in bar] == ["gateway", "static", "dhcp", "reserved"]
      and abs(sum(b["w"] for b in bar) - 1000) < 2 and next(b for b in bar if b["kind"] == "dhcp")["used"] == 2, bar)
big = subnet_map(BIG, [r for r in plan_rows(PLAN) if r["subnet"] == BIG["cidr"]])
check("a /16: a handful of rows, never 65,000; the gaps around its range drawn as 'none'",
      len(big["rows"]) <= 5 and [b["kind"] for b in big["bar"]] == ["none", "dhcp", "none"]
      and big["counts"]["size"] == 65534, (len(big["rows"]), big["bar"]))

print("--- options and their sources (1.10.4.6, 1.10.4.21)")
own = fabric_options(V, "10.1.20.1")
check("fabric provides the router, DNS, NTP, the domain and its search list", [o["name"] for o in own] ==
      ["routers", "domain-name-servers", "ntp-servers", "domain-name", "domain-search"]
      and own[1]["data"] == "192.168.1.2" and own[4]["data"] == "dhcp.home.arpa, home.arpa", own)
check("with dhcp.dns set, fabric's DNS option names those servers",
      fabric_options({**V, "dhcp": {"dns": ["9.9.9.9"]}})[0]["data"] == "9.9.9.9")
opts = subnet_options({"fabric": own, "settings": V["dhcp"]["options"], "subnet": IOT["options"]})
ntp = [o for o in opts if o["name"] == "ntp-servers"]
check("each option by name and code; fabric's marked provided; the subnet's NTP overrides fabric's",
      all(o["code"] for o in opts) and ntp[0]["provided"] and ntp[0]["overridden"] == "subnet"
      and ntp[1]["source"] == "subnet" and not ntp[1]["provided"], opts)
check("an option by code only shows its standard name (67, boot-file-name)",
      subnet_options({"reservation": [{"code": 67, "data": "x"}]})[0]["name"] == "boot-file-name")
check("a code Kea has no standard name for shows its code alone",
      subnet_options({"subnet": [{"code": 224, "data": "x"}]})[0] == {
          "name": "", "code": 224, "data": "x", "source": "subnet", "provided": False, "overridden": ""})
with_org = subnet_options({"fabric": own, "organisation": [{"name": "domain-name-servers", "data": "10.0.0.53"}]})
check("a level another part of fabric fills (the organisation's) appears as soon as its data does, and overrides "
      "fabric's own", any(o["source"] == "organisation" for o in with_org)
      and next(o for o in with_org if o["name"] == "domain-name-servers")["overridden"] == "organisation")

print("--- a site's view")
view = networks_view(V, READ, "lan", SITES, LEASES)
iot = view["vlans"][0]["subnets"][0]
check("the site's VLANs with their subnets, each drawn, its options and a reservation's own",
      [x["id"] for x in view["vlans"]] == [20, 90] and iot["bar"] and iot["rows"] and iot["options"]
      and "10.1.20.150" in iot["reservation_options"] and "addresses" not in iot and view["leases_shown"], iot.keys())
check("the sites listed with their numbers and suggestions",
      [(s["name"], s["block"], s["own"]) for s in view["sites"]] == [("lan", 1, True), ("parents", None, False)]
      and view["sites"][1]["suggested"] == 2, view["sites"])
other = networks_view(V, READ, "parents", SITES, None)
check("another site's view: no fabric or settings options of this site's, no leases",
      not any(o["source"] in ("fabric", "settings") for o in other["vlans"][0]["subnets"][0]["options"])
      and not other["leases_shown"])

print("--- the site scope (2.1.10.27)")
m_sites.load_registry = lambda: {"sites": {"parents": {}, "brother": {}}, "upstream": None}
# covers: agent:get.networks.* +
check("this site and the sites below it are shown; the request's case does not matter",
      site_scope(V, "") == "lan" and site_scope(V, "Parents") == "parents" and site_scope(V, "brother") == "brother")
# covers: agent:get.networks.* -
check("refused: a site that is not this one or below it, naming the ones shown",
      refused(lambda: site_scope(V, "upstairs"), "not this site or one below it") is True)
m_sites.load_registry = lambda: {"sites": {}, "upstream": {"name": "top"}}
check("a house sees only itself: its parent is refused", refused(lambda: site_scope({**V, "site_name": "parents"},
                                                                                  "lan"), "not this site") is True)

print("--- the agent's permission table (1.10.4.9: reading needs dhcp:read, changing dhcp:write)")
check("GET /v1/networks, /<site>, /<site>/export need dhcp:read",
      {required_permission("GET", r) for r in (["networks"], ["networks", "lan"], ["networks", "lan", "export"])}
      == {"dhcp:read"})
writes = (["networks", "lan", "block"], ["networks", "lan", "vlans"], ["networks", "lan", "vlans", "20"],
          ["networks", "lan", "vlans", "20", "delete"], ["networks", "lan", "subnets"],
          ["networks", "lan", "subnets", "iot"], ["networks", "lan", "subnets", "iot", "delete"],
          ["networks", "lan", "ranges"], ["networks", "lan", "ranges", "delete"], ["networks", "lan", "addresses"],
          ["networks", "lan", "addresses", "10.1.20.5"], ["networks", "lan", "addresses", "10.1.20.5", "delete"])
check("every change route needs dhcp:write", {required_permission("POST", r) for r in writes} == {"dhcp:write"})
check("refused: a route the table does not list (default deny)",
      required_permission("POST", ["networks", "lan", "vlans", "20", "move"]) is None
      and required_permission("GET", ["networks", "lan", "export", "x"]) is None)

print("--- the 0.7 commands as aliases (1.10.4.21): refusals that need no domain")
check("a pool as typed splits into its two addresses", pool_text(" 10.1.20.100 - 10.1.20.200 ") == (
    "10.1.20.100", "10.1.20.200"))
check("refused: a pool that is not two addresses", refused(lambda: pool_text("10.1.20.100"), "two addresses") is True)
check("refused: set-subnet with nothing to change", refused(lambda: set_dhcp_subnet(V, "root", "iot", router=KEEP),
                                                            "nothing to change") is True)
check("refused: unreserve with something that is not a MAC",
      refused(lambda: remove_reservation_mac(V, "root", "nope"), "not a MAC") is True)
m_dhcp.plan_holds_subnets = lambda data: True
m_dhcp.load_vars = lambda: {}


def dhcp(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = m_dhcp.run_dhcp_command(V, list(argv))
    return code, out.getvalue() + err.getvalue()


# covers: cli:dhcp.set-subnet -
code, text = dhcp("set-subnet", "iot", "--name", "cams")
check("refused: set-subnet --name once the subnets live in the plan (exit 1, saying where names change)",
      code == 1 and "stay in the address plan" in text, (code, text))
# covers: cli:dhcp.add-subnet -
code, text = dhcp("add-subnet", "10.1.40.0/24", "--name", "x", "--vlan", "forty")
check("refused: add-subnet with a VLAN that is not a number (exit 1)", code == 1 and "1 to 4094" in text,
      (code, text))
code, text = dhcp("add-subnet", "10.1.40.0/24")
check("an alias form it does not know prints the usage (exit 2)", code == 2 and "usage" in text, (code, text))
# covers: cli:dhcp.unreserve -
code, text = dhcp("unreserve", "zz")
check("refused: unreserve with a bad MAC (exit 1)", code == 1 and "not a MAC" in text, (code, text))

print("--- the agent's Networks routes, each accepted and refused (fabriclib's writes stubbed; tests/samba/ipam.py "
      "runs them against a real DC)")
import agent.get_route as m_get  # noqa: E402
import agent.post_networks as m_post  # noqa: E402
import fabriclib.ipam.networks_csv as m_csv  # noqa: E402
import fabriclib.ipam.networks_overview as m_over  # noqa: E402
import webui.routes.networks_post as m_web  # noqa: E402

m_sites.load_registry = lambda: {"sites": {"parents": {}}, "upstream": None}
m_get.load_vars = m_post.load_vars = lambda: dict(V)
CALLS, APPLIES = [], []


def plan_ok(v, secrets=None, of=None, **_kw):
    return READ


def plan_down(v, secrets=None, of=None, **_kw):
    raise ValidationError("the DC did not answer")


def recorder(name):
    def fn(v, actor, *args, **kw):
        site = next((a for a in args if a in ("lan", "parents")), "lan")
        CALLS.append((name, args, kw))
        return {"result": name, "warnings": [], "done": True, "site": site}
    return fn


for fname in ("set_block", "add_vlan", "set_vlan", "remove_vlan", "add_subnet", "set_subnet", "remove_subnet",
              "add_range", "remove_range", "add_address", "set_address", "remove_address"):
    setattr(m_post, fname, recorder(fname))
m_post.apply_changes = lambda actor, source="": APPLIES.append(actor) or (True, "applied")
m_post.refresh_firewall = lambda: (True, "")
m_over.read_plan = m_csv.read_plan = plan_ok
m_over.load_plan_cache = lambda: None
# covers: agent:get.networks +
out = m_get.get_route(["networks"])
check("GET /v1/networks: this site's plan drawn, the sites this console shows", out["site"] == "lan" and
      out["own"] == "lan" and not out["error"], out.get("error"))
# covers: agent:get.networks.* +
out = m_get.get_route(["networks", "Parents"])
check("GET /v1/networks/<site>: a site below this one", out["site"] == "parents" and not out["error"], out.get("site"))
# covers: agent:get.networks.* -
check("refused: GET /v1/networks/<site> for a site this console does not show (400, naming why)",
      refused(lambda: m_get.get_route(["networks", "upstairs"]), "not this site or one below it") is True)
# covers: agent:get.networks.*.export +
out = m_get.get_route(["networks", "lan", "export"])
check("GET /v1/networks/<site>/export: the address table as CSV, a safe file name",
      out["name"] == "lan-addresses.csv" and "10.1.20.10" in out["csv"], out)
m_over.read_plan = m_csv.read_plan = plan_down
# covers: agent:get.networks -
out = m_get.get_route(["networks"])
check("GET /v1/networks with the DC down and no kept copy: says why, never fails",
      out["error"].startswith("the plan could not be read") and out["vlans"] == [], out.get("error"))
# covers: agent:get.networks.*.export -
check("refused: an export with the DC down (400; never a stale copy)",
      refused(lambda: m_get.get_route(["networks", "lan", "export"]), "did not answer") is True)
m_over.read_plan = m_csv.read_plan = plan_ok

ROUTES = [  # (id, sub-route, body, function called, (a refused site, sub-route, body), words)
    ("block", ["block"], {"number": "3"}, "set_block", ("upstairs", ["block"], {"number": "3"}), "not this site"),
    ("vlans", ["vlans"], {"id": "40", "name": "lab"}, "add_vlan", ("lan", ["vlans"], {"id": "abc", "name": "lab"}),
     "1 to 4094"),
    ("vlans.*", ["vlans", "20"], {"name": "cams"}, "set_vlan", ("lan", ["vlans", "x20"], {"name": "cams"}),
     "1 to 4094"),
    ("vlans.*.delete", ["vlans", "20", "delete"], {}, "remove_vlan",
     ("lan", ["vlans", "20", "delete"], {"force": "maybe"}), "force is on or off"),
    ("subnets", ["subnets"], {"vlan": "40", "cidr": "10.1.40.0/24"}, "add_subnet",
     ("lan", ["subnets"], {"vlan": "forty", "cidr": "10.1.40.0/24"}), "1 to 4094"),
    ("subnets.*", ["subnets", "iot"], {"notes": "cams"}, "set_subnet",
     ("lan", ["subnets", "iot"], {"dhcp": "maybe"}), "dhcp is on or off"),
    ("subnets.*.delete", ["subnets", "iot", "delete"], {}, "remove_subnet",
     ("upstairs", ["subnets", "iot", "delete"], {}), "not this site"),
    ("ranges", ["ranges"], {"vlan": "20", "kind": "static", "first": "10.1.20.2", "last": "10.1.20.9"}, "add_range",
     ("lan", ["ranges"], {"vlan": "", "kind": "static", "first": "10.1.20.2", "last": "10.1.20.9"}), "1 to 4094"),
    ("ranges.delete", ["ranges", "delete"], {"vlan": "20", "first": "10.1.20.2"}, "remove_range",
     ("lan", ["ranges", "delete"], {"vlan": 20, "first": "10.1.20.2"}), "must be text"),
    ("addresses", ["addresses"], {"ip": "10.1.20.11", "kind": "static", "name": "printer"}, "add_address",
     ("lan", ["addresses"], {"ip": "10.1.20.11", "kind": "static", "dns": "maybe"}), "dns is on or off"),
    ("addresses.*", ["addresses", "10.1.20.10"], {"owner": "office"}, "set_address",
     ("lan", ["addresses", "10.1.20.10"], {"dns": "maybe"}), "dns is on or off"),
    ("addresses.*.delete", ["addresses", "10.1.20.10", "delete"], {}, "remove_address",
     ("upstairs", ["addresses", "10.1.20.10", "delete"], {}), "not this site")]
for ident, sub, body, fname, (bad_site, bad_sub, bad_body), words in ROUTES:
    del CALLS[:], APPLIES[:]
    out = m_post.post_networks(["networks", "lan", *sub], "alice", body)
    # covers: agent:post.networks.*.block agent:post.networks.*.vlans agent:post.networks.*.vlans.* +
    # covers: agent:post.networks.*.vlans.*.delete agent:post.networks.*.subnets agent:post.networks.*.subnets.* +
    # covers: agent:post.networks.*.subnets.*.delete agent:post.networks.*.ranges +
    # covers: agent:post.networks.*.ranges.delete agent:post.networks.*.addresses +
    # covers: agent:post.networks.*.addresses.* agent:post.networks.*.addresses.*.delete +
    check(f"POST /v1/networks/<site>/{ident.replace('.', '/')}: {fname}, as the user, source web; applied unless "
          "it is the site's number", [c[0] for c in CALLS] == [fname] and CALLS[0][2].get("source") == "web"
          and out["own"] and (out["applied"] is None) == (sub == ["block"]) and len(APPLIES) == (sub != ["block"]),
          (CALLS, out))
    del CALLS[:], APPLIES[:]
    # covers: agent:post.networks.*.block agent:post.networks.*.vlans agent:post.networks.*.vlans.* -
    # covers: agent:post.networks.*.vlans.*.delete agent:post.networks.*.subnets agent:post.networks.*.subnets.* -
    # covers: agent:post.networks.*.subnets.*.delete agent:post.networks.*.ranges -
    # covers: agent:post.networks.*.ranges.delete agent:post.networks.*.addresses -
    # covers: agent:post.networks.*.addresses.* agent:post.networks.*.addresses.*.delete -
    check(f"refused: POST /v1/networks/<site>/{ident.replace('.', '/')} ({words}): nothing written or applied",
          refused(lambda: m_post.post_networks(["networks", bad_site, *bad_sub], "alice", bad_body), words) is True
          and not CALLS and not APPLIES, CALLS)
out = m_post.post_networks(["networks", "parents", "vlans"], "alice", {"id": "40", "name": "lab"})
check("a change to a site below this one is written for its next apply, never applied here",
      out["site"] == "parents" and not out["own"] and out["applied"] is None, out)

print("--- the console's Networks forms, each accepted and refused (the agent stubbed; tests/webui runs them for real)")


class Page:
    def redirect(self, url):
        return 303, url

    def deny(self, code, text):
        return code, text


SENT = []


def agent_ok(site, parts, body):
    SENT.append((site, parts, body))
    return {"result": "", "warnings": [], "site": site, "own": site == "lan", "applied": True, "output": ""}


def agent_no(site, parts, body):
    raise m_web.actions.ValidationError(f"the agent refused {'/'.join(parts)}")


for ident, sub, body, _fname, _bad, _words in ROUTES:
    m_web.actions.networks_change = agent_ok
    del SENT[:]
    st, url = m_web.networks_post(Page(), ["lan", *sub], {"csrf": "x", "back": "iot", "evil": "1", **body})
    # covers: web:post.networks.*.block web:post.networks.*.vlans web:post.networks.*.vlans.* +
    # covers: web:post.networks.*.vlans.*.delete web:post.networks.*.subnets web:post.networks.*.subnets.* +
    # covers: web:post.networks.*.subnets.*.delete web:post.networks.*.ranges web:post.networks.*.ranges.delete +
    # covers: web:post.networks.*.addresses web:post.networks.*.addresses.* +
    # covers: web:post.networks.*.addresses.*.delete +
    check(f"console: POST /networks/<site>/{ident.replace('.', '/')} is one agent call with the form's own fields, "
          "back to the subnet with what happened", st == 303 and "msg=" in url and "subnet=iot" in url
          and SENT and SENT[0][1] == sub and "evil" not in SENT[0][2] and "csrf" not in SENT[0][2], (st, url, SENT))
    m_web.actions.networks_change = agent_no
    st, url = m_web.networks_post(Page(), ["lan", *sub], {"csrf": "x", **body})
    # covers: web:post.networks.*.block web:post.networks.*.vlans web:post.networks.*.vlans.* -
    # covers: web:post.networks.*.vlans.*.delete web:post.networks.*.subnets web:post.networks.*.subnets.* -
    # covers: web:post.networks.*.subnets.*.delete web:post.networks.*.ranges web:post.networks.*.ranges.delete -
    # covers: web:post.networks.*.addresses web:post.networks.*.addresses.* -
    # covers: web:post.networks.*.addresses.*.delete -
    check(f"console: refused POST /networks/<site>/{ident.replace('.', '/')}: back to the tab with the agent's why",
          st == 303 and "err=" in url and "msg=" not in url and "agent+refused" in url, (st, url))
m_web.actions.networks_change = agent_ok
check("console: a path the tab does not have is 404, nothing sent",
      m_web.networks_post(Page(), ["lan", "vlans", "20", "move"], {})[0] == 404
      and m_web.networks_post(Page(), ["", "vlans"], {})[0] == 404)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
