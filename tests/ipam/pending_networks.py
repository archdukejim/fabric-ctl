#!/usr/bin/env python3
"""The `ipam` suite, the address manager's held changes (manual 1.10.4.40.2, 1.10.4.40.3) with no container: the page
each route is held on, its sentence, its thing and key, the grant's networks right checked when it is held and again
at Apply (agent/pending_networks, the store's check), the held change run without its own apply (post_pending._run)
and the page's finish applying this site's plan once (post_pending._finish_plan), each accepted and refused. The DC's
reads, the grants and the apply are stood in for (their own cases: networks.py, agent_routes.py, tests/samba).

    python3 tests/ipam/pending_networks.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
import agent.pending_networks as m_pn  # noqa: E402
import agent.pending_thing as m_thing  # noqa: E402
import agent.post_ipam_scan as m_scan  # noqa: E402
import agent.post_networks as m_net  # noqa: E402
import agent.post_options as m_opt  # noqa: E402
import agent.post_pending as m_pp  # noqa: E402
import fabriclib.access.check_access as m_access  # noqa: E402
import fabriclib.ipam.read_plan as m_read  # noqa: E402
import fabriclib.security.refresh_firewall as m_fw  # noqa: E402
import fabriclib.system.apply_changes as m_apply  # noqa: E402
from agent.pending_store import PendingStore  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
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


V = {"site_name": "lan", "install_kea": True}
m_pn._this_site = lambda: "lan"
m_pp.load_vars = lambda: dict(V)
ASKED = []                                    # (caller, action, site) the grant was asked for
DENY = set()                                  # (caller, action, site) the grants refuse


def fake_check_access(v, caller, action, target=None, container="samba"):
    site = (target or {}).get("site")
    ASKED.append((caller, action, site))
    if (caller, action, site) in DENY:
        raise ValidationError(f"no grant gives you {action.replace(':', ' ')} at {site} (manual 1.10.4.34)")
    return {"by": "grant"}


m_access.check_access = fake_check_access
PLANS = {"lan": {"vlans": [{"id": 20, "name": "iot"}], "subnets": [], "networks": []},
         "lab": {"vlans": [], "subnets": [], "networks": []}}


def fake_read_plan(v, secrets=None, of="", container="samba"):
    if of not in PLANS:
        raise ValidationError(f"no such site: {of}")
    return {"sites": [{"name": s, "block": None} for s in PLANS], "plans": {of: PLANS[of]},
            "option_sets": {"domain": {"options": [{"name": "ntp-servers", "data": "10.1.10.4"}]},
                            of: {"options": []}}}


m_read.read_plan = fake_read_plan

print("--- the page each change is held on (networks_page_of, pending_thing)")
check("a site's plan and a scan's find are Networks'",
      [m_pn.networks_page_of(r) for r in (["networks", "lan", "vlans"], ["networks", "lab", "block"],
                                         ["networks", "lan", "addresses", "10.1.20.5", "delete"],
                                         ["ipam", "scan", "record"])] == ["networks"] * 4)
check("options, classes, definitions and netboot are DHCP options'",
      [m_pn.networks_page_of(["ipam", k]) for k in ("options", "classes", "option-defs", "netboot")]
      == ["options"] * 4)
check("a scan, a request, Sync now, a read and another area's change are not held here",
      [m_pn.networks_page_of(r) for r in (["ipam", "scan"], ["ipam", "scan", "request"], ["ipam", "sync"],
                                         ["networks", "lan"], ["networks", "", "vlans"], ["zones"],
                                         ["people", "bob"])] == [None] * 7)
check("pending_thing names the pages, each seen with dhcp:read",
      m_thing.pending_page_of(["networks", "lan", "vlans"]) == "networks"
      and m_thing.pending_page_of(["ipam", "netboot"]) == "options"
      and m_thing.PAGES["networks"] == m_thing.PAGES["options"] == "dhcp:read")
check("every held route needs dhcp:write (checked at hold and at Apply by the store)",
      {required_permission("POST", r) for r in (["networks", "lan", "vlans"], ["networks", "lan", "block"],
                                               ["ipam", "scan", "record"], ["ipam", "options"],
                                               ["ipam", "netboot"])} == {"dhcp:write"})

print("--- what each change says (describe_networks)")
SAYS = [(["networks", "lan", "vlans"], {"id": "30", "name": "cams"}, "Add VLAN 30 (cams) at lan"),
        (["networks", "lab", "vlans", "30", "delete"], {}, "Remove VLAN 30 at lab"),
        (["networks", "lan", "subnets"], {"cidr": "10.1.31.0/24", "vlan": "30"},
         "Add subnet 10.1.31.0/24 to VLAN 30 at lan"),
        (["networks", "lan", "ranges"], {"kind": "dhcp", "first": "10.1.30.100", "last": "10.1.30.199"},
         "Add dhcp range 10.1.30.100 - 10.1.30.199 at lan"),
        (["networks", "lan", "addresses"], {"ip": "10.1.20.9", "kind": "static"}, "Record 10.1.20.9 as static at lan"),
        (["networks", "lan", "block"], {"number": "7"}, "Set the site's number to 7 at lan"),
        (["ipam", "scan", "record"], {"ip": "10.1.20.77", "kind": "reservation"},
         "Record 10.1.20.77 (found by a scan) as a reservation at lan"),
        (["ipam", "options"], {"action": "set", "scope": "domain", "option": "ntp-servers"},
         "Set option ntp-servers in the domain's set"),
        (["ipam", "options"], {"action": "remove", "scope": "subnet", "target": "iot", "option": "67", "site": "lab"},
         "Remove option 67 on subnet iot at lab"),
        (["ipam", "classes"], {"action": "add", "name": "uefi", "scope": "site"}, "Add client class uefi at lan"),
        (["ipam", "netboot"], {"action": "off", "target": "iot"}, "Switch network boot off for iot at lan")]
for route, body, words in SAYS:
    said = m_thing.describe_change(route, body)
    check(f"{'/'.join(route)}: {words!r}", said == words, said)

print("--- the thing and its key (networks_state, networks_key)")
state = m_thing.thing_state(["networks", "lan", "vlans"], {"id": "30"}, dict(V))
check("a site's change reads that site's plan, nested so no body field is taken for one of its own",
      list(state) == ["plan"] and state["plan"]["vlans"] == PLANS["lan"]["vlans"] and "read" not in state["plan"],
      state)
check("the domain's set is its own thing (and a class of it)",
      m_thing.thing_state(["ipam", "options"], {"scope": "domain"}, dict(V)) == {
          "domain_options": {"options": [{"name": "ntp-servers", "data": "10.1.10.4"}]}}
      and m_thing.thing_key(["ipam", "options"], {"scope": "class", "domain": True}) == ("plan", "domain"))
check("every change to one site shares its key; another site's does not",
      m_thing.thing_key(["networks", "lan", "vlans"], {}) == m_thing.thing_key(["ipam", "options"], {})
      == ("plan", "lan") and m_thing.thing_key(["networks", "lab", "block"], {}) == ("plan", "lab"))
check("a site that is not the domain's: refused, nothing held",
      refused(lambda: m_thing.thing_state(["networks", "nowhere", "vlans"], {}, dict(V)), "no such site: nowhere"))

print("--- a site not there is a 404 at the agent's reads (agent/one_thing, 1.10.4.40.1)")
from agent.one_thing import one_thing  # noqa: E402
from fabriclib.common.errors import NotFound  # noqa: E402


def no_site(v, site):
    raise ValidationError(f"no such site: {site}")


def dc_down(v, site):
    raise ValidationError("the domain controller is not running")


try:
    one_thing(no_site, V, "nowhere")
    check("no such site: NotFound (404)", False, "not refused")
except NotFound as exc:
    check("no such site: NotFound (404)", str(exc) == "no such site: nowhere", exc)
try:
    one_thing(dc_down, V, "lab")
    check("the DC not running: a plain refusal (400), not a 404", False, "not refused")
except NotFound:
    check("the DC not running: a plain refusal (400), not a 404", False, "NotFound")
except ValidationError:
    check("the DC not running: a plain refusal (400), not a 404", True)

print("--- the grant at the change's site (networks_grant)")
ASKED.clear()
m_pn.networks_grant(V, "alice", ["networks", "lab", "vlans"], {})
m_pn.networks_grant(V, "alice", ["ipam", "options"], {"site": "lab"})
m_pn.networks_grant(V, "alice", ["ipam", "classes"], {"scope": "domain"})
m_pn.networks_grant(V, "alice", ["ipam", "scan", "record"], {})
m_pn.networks_grant(V, "alice", ["people", "bob"], {})
check("plan at the route's site, options at the body's, options at all for the domain's, plan here for a find; "
      "another area's change asks nothing",
      ASKED == [("alice", "networks:plan", "lab"), ("alice", "networks:options", "lab"),
                ("alice", "networks:options", "all"), ("alice", "networks:plan", "lan")], ASKED)
DENY.add(("bob", "networks:plan", "lab"))
check("no grant at the site: refused, saying which right at which site",
      refused(lambda: m_pn.networks_grant(V, "bob", ["networks", "lab", "vlans"], {}),
              "no grant gives you networks plan at lab"))

print("--- the store: the grant checked when held and again at Apply")
RAN = []


def make_store():
    return PendingStore(run=lambda route, actor, body, perms, session: RAN.append(route) or {"ok": True},
                        state=lambda route, body: m_thing.thing_state(route, body, dict(V)),
                        need=lambda route: required_permission("POST", route),
                        start_job=lambda kind, owner, fn: {"id": "j1", "result": fn()},
                        finish=lambda page, routes: None,
                        check=lambda owner, route, body: m_pn.networks_grant(V, owner, route, body))


store = make_store()
held = store.hold("alice", {"dhcp:write", "dhcp:read"}, "networks", ["networks", "lab", "vlans"],
                  {"id": "30", "name": "cams"}, "Add VLAN 30 (cams) at lab")
check("held with the grant", held["pending"] == 1, held)
check("held without the grant: refused, nothing held",
      refused(lambda: store.hold("bob", {"dhcp:write"}, "networks", ["networks", "lab", "vlans"], {"id": "31"},
                                 "Add VLAN 31 at lab"), "no grant gives you networks plan at lab") is True
      and not store.page("bob", "networks", lambda page: True)["changes"])
check("held without dhcp:write: refused before the grant is asked",
      refused(lambda: store.hold("carol", {"dhcp:read"}, "networks", ["networks", "lab", "vlans"], {}, "x"),
              "you need the permission dhcp:write") is True and all(a[0] != "carol" for a in ASKED))
DENY.add(("alice", "networks:plan", "lab"))          # the grant taken away between the hold and the Apply
job = store.apply("alice", {"dhcp:write", "dhcp:read"}, "networks", "alice", None)["result"]
check("the grant taken away before Apply: refused there, nothing run, the change left pending",
      job["applied"] == 0 and job["items"][0]["state"] == "failed"
      and "refused: no grant gives you networks plan at lab" in job["items"][0]["why"] and not RAN
      and store.page("alice", "networks", lambda page: True)["changes"], job)
DENY.discard(("alice", "networks:plan", "lab"))
job = store.apply("alice", {"dhcp:write", "dhcp:read"}, "networks", "alice", None)["result"]
check("the grant back: applied", job["applied"] == 1 and RAN == [["networks", "lab", "vlans"]], job)

print("--- a held change runs without its own apply (post_pending._run)")
CALLED = []
m_net.post_networks = lambda route, actor, data, caller=None, apply=True: CALLED.append(
    ("networks", route, caller, apply)) or {}
m_scan.post_ipam_scan = lambda route, actor, data, caller=None, apply=True: CALLED.append(
    ("scan", route, caller, apply)) or {}
m_opt.post_options = lambda route, actor, data, caller=None, apply=True: CALLED.append(
    ("options", route, caller, apply)) or {}
for route in (["networks", "lan", "vlans"], ["ipam", "scan", "record"], ["ipam", "netboot"]):
    m_pp._run(route, "alice", {}, {"dhcp:write"}, None)
check("each by its own route, the person as the caller the grant is checked for, apply=False",
      CALLED == [("networks", ["networks", "lan", "vlans"], "alice", False),
                 ("scan", ["ipam", "scan", "record"], "alice", False),
                 ("options", ["ipam", "netboot"], "alice", False)], CALLED)

print("--- the finish: this site's plan applied once (post_pending._finish_plan)")
APPLIES = []
m_apply.apply_changes = lambda actor, source="": APPLIES.append(("apply", actor, source)) or (True, "ok")
m_fw.refresh_firewall = lambda: APPLIES.append(("firewall",)) or (True, "ok")
last = m_pp._finish("networks", [["networks", "lan", "vlans"], ["networks", "lab", "vlans"]])
check("a change to this site's plan: one apply at the end", last is not None and "Kea" in last[0], last)
last[1]("alice")
check("the apply, then the firewall in line", APPLIES == [("apply", "alice", "web"), ("firewall",)], APPLIES)
check("only another site's changes, or this site's number: no finish (its poll takes it; a number is never applied)",
      m_pp._finish("networks", [["networks", "lab", "vlans"]]) is None
      and m_pp._finish("networks", [["networks", "lan", "block"]]) is None)
check("a scan's find recorded is this site's: finished",
      m_pp._finish("networks", [["ipam", "scan", "record"]]) is not None)
check("DHCP options: always finished", m_pp._finish("options", [["ipam", "options"]]) is not None)
m_apply.apply_changes = lambda actor, source="": (False, "render\nkea did not come up")
check("an apply that does not finish: refused with its last line, the firewall not touched",
      refused(lambda: m_pp._finish("options", [["ipam", "options"]])[1]("alice"),
              "the apply did not finish: kea did not come up"))
m_apply.apply_changes = lambda actor, source="": (True, "ok")
m_fw.refresh_firewall = lambda: (False, "nft refused")
check("a firewall that does not come in line: refused",
      refused(lambda: m_pp._finish("options", [["ipam", "options"]])[1]("alice"), "nft refused"))

print("--- the routes' own apply keyword (post_networks, post_options, post_ipam_scan)")
import importlib  # noqa: E402
SEEN = []
for mod in ("agent.post_networks", "agent.post_options", "agent.post_ipam_scan"):
    importlib.reload(sys.modules[mod])
import agent.post_ipam_scan as r_scan  # noqa: E402
import agent.post_networks as r_net  # noqa: E402
import agent.post_options as r_opt  # noqa: E402
for mod in (r_net, r_opt, r_scan):
    mod.load_vars = lambda: dict(V)
    mod.apply_plan_change = lambda v, actor, out, apply=True: SEEN.append(apply) or {"applied": None}
r_net._change = lambda v, actor, site, rest, data, caller: {"result": {}, "site": site}
r_opt._change = lambda v, kind, data, actor, caller: ("option", {"result": {}})
r_scan.add_address = lambda *a, **kw: {"result": {"ip": "10.1.20.77"}}
r_net.post_networks(["networks", "lan", "vlans"], "alice", {}, "alice")
r_net.post_networks(["networks", "lan", "vlans"], "alice", {}, "alice", apply=False)
r_net.post_networks(["networks", "lan", "block"], "alice", {}, "alice")
r_opt.post_options(["ipam", "options"], "alice", {}, "alice", apply=False)
r_scan.post_ipam_scan(["ipam", "scan", "record"], "alice", {"ip": "10.1.20.77", "kind": "static"}, "alice",
                      apply=False)
check("a direct call applies (but the site's number); a held one does not",
      SEEN == [True, False, False, False, False], SEEN)

print("FAILED" if FAILED else "all passed", FAILED)
sys.exit(1 if FAILED else 0)
