#!/usr/bin/env python3
"""The `ipam` suite, the agent's address-manager routes beside the Networks ones (manual 1.10.4.35) with no container:
the options page's reads (GET /v1/ipam/options/<site>[/<target>]) and changes (POST /v1/ipam/options, classes,
option-defs, netboot: the domain's set as `scope` domain, the /org routes gone), Sync now (POST /v1/ipam/sync, the
grant's networks plan right checked first), the scans (GET /v1/ipam/scan: the subnets and whether this person may
scan; POST /v1/ipam/scan, /scan/record, /scan/request), each accepted and refused, with the permission each needs.
The functions below the routes are stood in for (their own cases: options.py, sync.py, scan.py, scan_requests.py);
tests/networks.py has the Networks routes.

    python3 tests/ipam/agent_routes.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
import agent.get_route as m_get  # noqa: E402
import agent.post_ipam_scan as m_scan  # noqa: E402
import agent.post_ipam_sync as m_sync  # noqa: E402
import agent.post_options as m_opt  # noqa: E402
import agent.post_route as m_route  # noqa: E402
import fabriclib.ipam.common.apply_plan_change as m_apply  # noqa: E402
import fabriclib.ipam.scan_overview as m_over  # noqa: E402
import fabriclib.ipam.sync.sync_plan as m_syncplan  # noqa: E402
from agent.route_not_found import RouteNotFound  # noqa: E402
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
    except RouteNotFound:
        return "404" if words == "404" else "404 (RouteNotFound)"
    return "not refused"


V = {"site_name": "lan", "install_kea": True, "dc_name": "dc1"}
CALLS, APPLIES = [], []
for m in (m_get, m_scan, m_sync, m_opt):
    m.load_vars = lambda: dict(V)
m_apply.apply_changes = lambda actor, source="": APPLIES.append(actor) or (True, "applied")
m_apply.refresh_firewall = lambda: (True, "in line")


def recorder(name, site_at=None):
    """A stand-in for a function that checks the grant: refuses bob, records the call."""
    def fn(v, actor, *args, **kw):
        if kw.get("caller") == "bob":
            raise ValidationError("no grant gives you networks options at lan (manual 1.6.13.12)")
        CALLS.append((name, args, kw))
        site = args[site_at] if site_at is not None and len(args) > site_at and args[site_at] else "lan"
        return {"result": name, "warnings": [], "done": True, "site": site}
    return fn


print("--- the permission each route needs")
check("reads need dhcp:read; changes, the scans and Sync now dhcp:write",
      {required_permission("GET", r) for r in (["ipam", "options", "lan"], ["ipam", "options", "lan", "site"],
                                               ["ipam", "scan"])} == {"dhcp:read"}
      and {required_permission("POST", ["ipam", *r]) for r in (["options"], ["classes"], ["option-defs"],
                                                               ["netboot"], ["sync"], ["scan"], ["scan", "record"],
                                                               ["scan", "request"])} == {"dhcp:write"})
check("0.8's /org routes, option-editors and local-scan are not routes (refused before the agent answers)",
      all(required_permission("POST", ["ipam", *r]) is None for r in (["options", "org"], ["classes", "org"],
                                                                     ["option-defs", "org"], ["option-editors"],
                                                                     ["local-scan"], ["scan-policy"])))

print("--- the options page (post_options, options_overview)")
SEEN = []
m_get.options_overview = lambda v, site, target: SEEN.append((site, target)) or {"site": site or "lan"}
# covers: agent:get.ipam.options.* agent:get.ipam.options.*.* +
out = m_get.get_route(["ipam", "options", "-"]), m_get.get_route(["ipam", "options", "parents", "subnet:iot"])
check("GET /v1/ipam/options/<site>[/<target>]: options_overview of the site (`-` this one) and the target",
      SEEN == [("", ""), ("parents", "subnet:iot")], SEEN)


def no_site(v, site, target):
    raise ValidationError(f"no such site: {site}")


m_get.options_overview = no_site
# covers: agent:get.ipam.options.* agent:get.ipam.options.*.* -
check("refused: a site that is not the domain's (400, naming it)",
      refused(lambda: m_get.get_route(["ipam", "options", "upstairs"]), "no such site: upstairs") is True
      and refused(lambda: m_get.get_route(["ipam", "options", "upstairs", "site"]), "no such site") is True)
for fname, at in (("set_plan_option", 4), ("remove_plan_option", 3), ("add_plan_class", 6), ("remove_plan_class", 2),
                  ("define_plan_option", 7), ("undefine_plan_option", 3), ("set_netboot", 2), ("clear_netboot", 1)):
    setattr(m_opt, fname, recorder(fname, at))
OPTS = [  # (route, body, function, refused body, words)
    ("options", {"action": "set", "scope": "subnet", "target": "iot", "option": "ntp-servers", "data": "10.1.0.9"},
     "set_plan_option", {"action": "change"}, "action: set or remove"),
    ("options", {"action": "remove", "scope": "domain", "option": "ntp-servers"}, "remove_plan_option",
     {"action": "remove", "scope": "domain", "option": 7}, "must be text"),
    ("classes", {"action": "add", "scope": "domain", "name": "uefi", "test": "option[93].hex == 0x0007"},
     "add_plan_class", {"action": "add", "scope": "org", "name": "uefi"}, "scope: domain or site"),
    ("classes", {"action": "remove", "name": "uefi"}, "remove_plan_class", {"action": "drop"},
     "action: add or remove"),
    ("option-defs", {"action": "define", "name": "vendor", "code": "224", "type": "string"}, "define_plan_option",
     {"action": "define", "scope": "everywhere"}, "scope: domain or site"),
    ("option-defs", {"action": "undefine", "name": "vendor"}, "undefine_plan_option", {"action": "x"},
     "action: define or undefine"),
    ("netboot", {"action": "on", "target": "subnet:iot", "server": "10.1.0.5", "uefi": "ipxe.efi"}, "set_netboot",
     {"action": "maybe"}, "action: on or off"),
    ("netboot", {"action": "off", "target": "subnet:iot"}, "clear_netboot", {"action": "on", "target": ["x"]},
     "must be text")]
for kind, body, fname, bad, words in OPTS:
    del CALLS[:], APPLIES[:]
    # covers: agent:post.ipam.options agent:post.ipam.classes agent:post.ipam.option-defs agent:post.ipam.netboot +
    out = m_route.post_route(["ipam", kind], "alice", body, ["dhcp:write"])
    check(f"POST /v1/ipam/{kind} ({body['action']}): {fname} as the signed-in person, source web; this site's change "
          "applied with the firewall", [c[0] for c in CALLS] == [fname] and CALLS[0][2] == {"source": "web",
                                                                                            "caller": "alice"}
          and out["own"] and out["applied"] is True and APPLIES == ["alice"], (CALLS, out))
    del CALLS[:], APPLIES[:]
    # covers: agent:post.ipam.options agent:post.ipam.classes agent:post.ipam.option-defs agent:post.ipam.netboot -
    check(f"refused: POST /v1/ipam/{kind} with a bad body ({words}): nothing written or applied",
          refused(lambda: m_route.post_route(["ipam", kind], "alice", bad, ["dhcp:write"]), words) is True
          and not CALLS and not APPLIES, refused(lambda: m_route.post_route(["ipam", kind], "alice", bad, []), words))
check("refused: a person without the grant's networks options right, before anything is written or applied",
      refused(lambda: m_route.post_route(["ipam", "options"], "bob", OPTS[0][1], ["dhcp:write"]), "no grant gives")
      is True and not CALLS and not APPLIES)
out = m_route.post_route(["ipam", "options"], "alice", {**OPTS[0][1], "site": "parents"}, ["dhcp:write"])
check("another site's change: left to its poll, never applied here", out["site"] == "parents" and not out["own"]
      and out["applied"] is None and not APPLIES, out)
out = m_route.post_route(["ipam", "classes"], "alice", {"action": "add", "name": "x", "test": "t"}, None)
check("a root peer acts for the Enterprise Admin (caller None)", CALLS[-1][2]["caller"] is None, CALLS[-1])
check("another path under /v1/ipam: 404", refused(lambda: m_route.post_route(["ipam", "options", "org"], "alice", {},
                                                                             ["dhcp:write"]), "404") == "404")

print("--- Sync now (post_ipam_sync, sync_plan's grant check)")
SYNCS = []
m_sync.sync_plan = lambda v, actor, source="cli", caller=None: SYNCS.append((actor, source, caller)) or {
    "state": "same plan", "kea_restarted": False, "firewall": False, "dns_pending": False, "dns": None}
# covers: agent:post.ipam.sync +
out = m_route.post_route(["ipam", "sync"], "alice", {}, ["dhcp:write"])
check("POST /v1/ipam/sync: sync_plan as the signed-in person, source web", SYNCS == [("alice", "web", "alice")]
      and out["state"] == "same plan", (SYNCS, out))
checked = []


def deny(v, caller, action, target=None, container="samba"):
    checked.append((caller, action, target))
    raise ValidationError("no grant gives you networks plan at lan (manual 1.6.13.12)")


# covers: agent:post.ipam.sync -
check("refused: sync_plan for a person without networks plan here, before the settings or the lock are touched",
      refused(lambda: m_syncplan.sync_plan(V, "bob", source="web", caller="bob", check=deny,
                                           settings=lambda: 1 / 0, take_lock=lambda: 1 / 0), "no grant gives") is True
      and checked == [("bob", "networks:plan", {"site": "lan"})], checked)
check("root (the CLI) is not asked about: it acts for the Enterprise Admin",
      refused(lambda: m_syncplan.sync_plan({**V, "install_kea": False}, "root", check=deny), "DHCP is off") is True
      and len(checked) == 1, checked)
check("another path under /v1/ipam/sync: 404",
      refused(lambda: m_route.post_route(["ipam", "sync", "now"], "alice", {}, ["dhcp:write"]), "404") == "404")

print("--- the scans (post_ipam_scan, scan_overview)")
m_over.scannable_subnets = lambda v: [{"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "dhcp": True,
                                       "hosts": 254}]
m_over.check_access = lambda v, caller, action, target=None, container="samba": {"tier": "delegated", "by": "grant"}
# covers: agent:get.ipam.scan +
out = m_get.get_route(["ipam", "scan"], "alice")
check("GET /v1/ipam/scan: the subnets a scan may cover, and this person may scan here", out["may"] is True
      and out["subnets"][0]["cidr"] == "10.1.20.0/24" and out["site"] == "lan", out)
m_over.check_access = deny
# covers: agent:get.ipam.scan -
out = m_get.get_route(["ipam", "scan"], "bob")
check("GET /v1/ipam/scan for a person without networks scan here: may is false, saying why (the subnets still "
      "listed)", out["may"] is False and "no grant gives" in out["why"] and out["subnets"], out)
SCANS = []


def scan(v, actor, subnet, source="cli", caller=None):
    if not subnet:
        raise ValidationError("name the subnet to scan: its name or its network")
    SCANS.append(("scan", actor, subnet, source, caller))
    return {"subnet": {"name": "iot", "cidr": "10.1.20.0/24"}, "unrecorded": 1}


def request(v, actor, site, subnet, source="cli", caller=None):
    if site == "lan":
        raise ValidationError("a scan of lan's own subnet runs here: fabricctl ipam scan <subnet>")
    SCANS.append(("request", actor, site, subnet, source, caller))
    return {"id": "scan-1", "site": site, "state": "pending"}


m_scan.scan_subnet, m_scan.request_scan = scan, request
m_scan.add_address = recorder("add_address", 2)
# covers: agent:post.ipam.scan agent:post.ipam.scan.request agent:post.ipam.scan.record +
out = m_route.post_route(["ipam", "scan"], "alice", {"subnet": "iot"}, ["dhcp:write"])
check("POST /v1/ipam/scan: scan_subnet as the signed-in person, source web", SCANS[-1] == ("scan", "alice", "iot",
                                                                                         "web", "alice")
      and out["unrecorded"] == 1, SCANS)
out = m_route.post_route(["ipam", "scan", "request"], "alice", {"site": "parents", "subnet": "iot"}, ["dhcp:write"])
check("POST /v1/ipam/scan/request: request_scan at the site named, as the signed-in person",
      SCANS[-1] == ("request", "alice", "parents", "iot", "web", "alice") and out["state"] == "pending", SCANS)
del CALLS[:], APPLIES[:]
out = m_route.post_route(["ipam", "scan", "record"], "alice", {"ip": "10.1.20.55", "mac": "aa:bb:cc:00:00:55",
                                                               "name": "cam4"}, ["dhcp:write"])
check("POST /v1/ipam/scan/record: a reservation for the MAC seen, noted as found by a scan, applied here",
      CALLS[0][0] == "add_address" and CALLS[0][1][:2] == ("10.1.20.55", "reservation")
      and "found by a scan" in CALLS[0][1][6] and CALLS[0][2]["caller"] == "alice" and out["applied"] is True
      and out["address"] == "add_address", (CALLS, out))
del CALLS[:], APPLIES[:]
# covers: agent:post.ipam.scan agent:post.ipam.scan.request agent:post.ipam.scan.record -
check("refused: a scan without a subnet, saying why", refused(lambda: m_route.post_route(
    ["ipam", "scan"], "alice", {}, ["dhcp:write"]), "name the subnet") is True)
check("refused: a request for this site's own subnet, saying why", refused(lambda: m_route.post_route(
    ["ipam", "scan", "request"], "alice", {"site": "lan", "subnet": "iot"}, ["dhcp:write"]), "runs here") is True)
check("refused: a find recorded as another kind, or by a person without the grant; nothing written or applied",
      refused(lambda: m_route.post_route(["ipam", "scan", "record"], "alice", {"ip": "10.1.20.55", "kind": "dhcp"},
                                         ["dhcp:write"]), "reservation or a static address") is True
      and refused(lambda: m_route.post_route(["ipam", "scan", "record"], "bob", {"ip": "10.1.20.55"},
                                             ["dhcp:write"]), "no grant gives") is True
      and not CALLS and not APPLIES, CALLS)
check("another path under /v1/ipam/scan: 404",
      refused(lambda: m_route.post_route(["ipam", "scan", "other"], "alice", {}, ["dhcp:write"]), "404") == "404")

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
