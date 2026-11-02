#!/usr/bin/env python3
"""The `ipam` suite, the Networks tab's model and its agent routes (manual 1.10.4.21, 1.10.4.35) with no container: a
subnet drawn as a map (its ranges as a bar, the counts, every address accounted for: the plan's, leases beside them,
unrecorded leases, free runs, a /16 in a handful of rows), the options with their sources and the "provided by
fabric" marker, another site's view without this site's options; what GET /v1/networks answers (any site of the
domain, the kept copy when the DC is down, another site refused then, the scan requests and the Sync now card), the
export, and each POST /v1/networks route accepted and refused (the grant's refusal from the function, a bad field),
this site's change applied with the firewall, another site's left to its poll, the site's number never applied. The
writes against a real DC: tests/samba/ipam.py; the console's pages come with area 9 of the port (1.10.4.41).

    python3 tests/ipam/networks.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.ipam.networks_view import networks_view  # noqa: E402
from fabriclib.ipam.plan_rows import plan_rows  # noqa: E402
from fabriclib.ipam.subnet_map import subnet_map  # noqa: E402
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

print("--- options and their sources, from effective_options (1.10.4.21.4, 2.3.10.5.7)")
ORG_SET = {"options": [{"name": "domain-name-servers", "data": "10.0.0.53"}], "option_defs": [], "client_classes": []}
SITE_SET = {"options": [], "option_defs": [],
            "client_classes": [{"name": "uefi", "test": "option[93].hex == 0x0007",
                                "options": [{"name": "ntp-servers", "data": "10.9.9.9"}]}]}
WITH_SETS = {**READ, "option_sets": {"domain": ORG_SET, "lan": SITE_SET}}
view = networks_view(V, WITH_SETS, "lan", SITES, LEASES)
iot = view["vlans"][0]["subnets"][0]
opts = {o["name"]: o for o in iot["options"]}
check("each option by name and code, with its source: fabric's router (the gateway), DNS and NTP marked provided",
      all(o["code"] for o in iot["options"]) and opts["routers"]["source"] == "fabric (the subnet's gateway)"
      and opts["routers"]["data"] == "10.1.20.1" and opts["domain-search"]["source"] == "fabric"
      and opts["domain-search"]["provided"], iot["options"])
check("the domain's DNS replaces fabric's, and says so", opts["domain-name-servers"]["source"] == "domain"
      and opts["domain-name-servers"]["overrides"] == ["fabric"] and opts["domain-name-servers"]["fabric_overridden"],
      opts["domain-name-servers"])
check("the subnet's NTP replaces fabric's; the settings' option not moved yet is shown as theirs",
      opts["ntp-servers"]["source"] == "subnet iot" and opts["ntp-servers"]["overrides"] == ["fabric"]
      and opts["time-offset"]["source"].startswith("settings"), (opts["ntp-servers"], opts["time-offset"]))
check("the site's class that may apply, its NTP marked as overridden by the subnet",
      iot["classes"][0]["name"] == "uefi" and iot["classes"][0]["owner"] == "site"
      and iot["classes"][0]["rows"][0]["overridden_by"] == "subnet iot", iot["classes"])
check("a reservation's own option by code shows its standard name (67, boot-file-name)",
      iot["reservation_options"]["10.1.20.150"] == [r for r in iot["reservation_options"]["10.1.20.150"]
                                                     if r["source"] == "address 10.1.20.150"]
      and iot["reservation_options"]["10.1.20.150"][0]["name"] == "boot-file-name"
      and iot["reservation_options"]["10.1.20.150"][0]["code"] == 67, iot["reservation_options"])
odd = networks_view(V, {**READ, "plans": {"lan": {**READ["plans"]["lan"], "subnets": [
    {**IOT, "options": [{"code": 224, "data": "x"}], "addresses": []}]}}}, "lan", SITES, None)
row = next(o for o in odd["vlans"][0]["subnets"][0]["options"] if o["code"] == 224)
check("a code Kea has no standard name for shows its code alone", row["name"] == "" and row["source"] == "subnet iot",
      row)
check("no VLAN-level options: a VLAN carries none of its own, its subnets' are shown",
      "options" not in {k for k in view["vlans"][0] if k != "subnets"} and iot["options"])

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
rows = other["vlans"][0]["subnets"][0]["options"]
check("another site's view: none of this install's settings, fabric's shown as that site's own, no leases",
      not any(o["source"].startswith("settings") for o in rows)
      and all(o["data"] == "(fabric's)" for o in rows if o["source"] == "fabric") and not other["leases_shown"], rows)

print("--- the agent's permission table (reading needs dhcp:read, changing dhcp:write; the grant is fabric-agent's)")
check("reading a site's plan needs dhcp:read",
      {required_permission("GET", r) for r in (["networks"], ["networks", "lan"], ["networks", "lan", "export"])}
      == {"dhcp:read"})
WRITES = [["networks", "lan", *s] for s in (["block"], ["vlans"], ["vlans", "20"], ["vlans", "20", "delete"],
                                            ["subnets"], ["subnets", "iot"], ["subnets", "iot", "delete"],
                                            ["ranges"], ["ranges", "delete"], ["addresses"],
                                            ["addresses", "10.1.20.10"], ["addresses", "10.1.20.10", "delete"])]
check("every change route needs dhcp:write", {required_permission("POST", r) for r in WRITES} == {"dhcp:write"})
check("a route not in the table is refused (no permission names it)",
      required_permission("POST", ["networks", "lan", "vlans", "20", "move"]) is None
      and required_permission("GET", ["networks", "lan", "export", "x"]) is None)

print("--- GET /v1/networks (networks_overview, networks_csv)")
import agent.get_route as m_get  # noqa: E402
import agent.post_networks as m_post  # noqa: E402
import fabriclib.ipam.common.apply_plan_change as m_apply  # noqa: E402
import fabriclib.ipam.networks_csv as m_csv  # noqa: E402
import fabriclib.ipam.networks_overview as m_over  # noqa: E402

VA = {**V, "install_kea": True}
m_get.load_vars = m_post.load_vars = lambda: dict(VA)
ASKED = []


def plan_ok(v, secrets=None, of=None, **_kw):
    ASKED.append(of)
    if of not in ("lan", "parents", ""):
        raise ValidationError(f"no such site: {of}")
    return READ


def plan_down(v, secrets=None, of=None, **_kw):
    raise ValidationError("the DC did not answer")


def requests(v, site, secrets=None, container="samba"):
    return [{"id": "scan-1", "site": site, "state": "pending"}]


m_over.list_scan_requests = requests
m_over.list_leases = m_csv.list_leases = lambda v: LEASES
m_over.sync_status = lambda v: {"kea": True, "polled": True, "usn": 7, "rendered": "", "dns_pending": True}
m_over.read_plan = m_csv.read_plan = plan_ok
m_over.load_plan_cache = lambda: None
# covers: agent:get.networks +
out = m_get.get_route(["networks"])
check("GET /v1/networks: this site's plan drawn, every site of the domain listed, its leases, the Sync now card",
      out["site"] == "lan" and out["own"] == "lan" and not out["error"] and out["leases_shown"]
      and [s["name"] for s in out["sites"]] == ["lan", "parents"] and out["sync"]["dns_pending"] is True
      and out["scan_requests"][0]["site"] == "lan", out.get("error"))
# covers: agent:get.networks.* +
out = m_get.get_route(["networks", "parents"])
check("GET /v1/networks/<site>: any site of the domain, without this site's leases or Sync now card; its scan "
      "requests", out["site"] == "parents" and not out["error"] and not out["leases_shown"] and out["sync"] is None
      and out["scan_requests"][0]["site"] == "parents", out.get("site"))
# covers: agent:get.networks.* -
check("refused: GET /v1/networks/<site> for a site that is not the domain's (400, naming it)",
      refused(lambda: m_get.get_route(["networks", "upstairs"]), "no such site: upstairs") is True)
# covers: agent:get.networks.*.export +
out = m_get.get_route(["networks", "lan", "export"])
check("GET /v1/networks/<site>/export: the address table as CSV, a safe file name",
      out["name"] == "lan-addresses.csv" and "10.1.20.10" in out["csv"], out)
m_over.read_plan = m_csv.read_plan = plan_down
# covers: agent:get.networks -
out = m_get.get_route(["networks"])
check("GET /v1/networks with the DC down and no kept copy: says why, never fails",
      out["error"].startswith("the plan could not be read") and out["vlans"] == [], out.get("error"))
m_over.load_plan_cache = lambda: {"site": "lan", "block": 1, "vlans": READ["plans"]["lan"]["vlans"],
                                  "subnets": [IOT], "networks": [], "read": "2026-10-23 10:00:00",
                                  "domain_options": None, "site_options": None}
out = m_get.get_route(["networks"])
check("the DC down with a kept copy: this site's plan as last read, saying so and when",
      not out["error"] and "as last read, at 2026-10-23 10:00:00" in out["stale"] and out["vlans"][0]["id"] == 20,
      (out["stale"], out["error"]))
check("refused: another site's plan with the DC down (never this site's copy shown as that site's)",
      refused(lambda: m_get.get_route(["networks", "parents"]), "did not answer") is True)
# covers: agent:get.networks.*.export -
check("refused: an export with the DC down (400; never a stale copy)",
      refused(lambda: m_get.get_route(["networks", "lan", "export"]), "did not answer") is True)
m_over.read_plan = m_csv.read_plan = plan_ok

print("--- POST /v1/networks (post_networks, apply_plan_change)")
CALLS, APPLIES = [], []


def recorder(name):
    def fn(v, actor, *args, **kw):
        site = next((a for a in args if a in ("lan", "parents", "upstairs")), "lan")
        if site == "upstairs":
            raise ValidationError("no grant gives you networks plan at upstairs (manual 1.6.13.12)")
        CALLS.append((name, args, kw))
        return {"result": name, "warnings": [], "done": True, "site": site}
    return fn


for fname in ("set_block", "add_vlan", "set_vlan", "remove_vlan", "add_subnet", "set_subnet", "remove_subnet",
              "add_range", "remove_range", "add_address", "set_address", "remove_address"):
    setattr(m_post, fname, recorder(fname))
m_apply.apply_changes = lambda actor, source="": APPLIES.append(actor) or (True, "applied")
m_apply.refresh_firewall = lambda: (True, "in line")
ROUTES = [  # (id, sub-route, body, function called, (a refused site, sub-route, body), words)
    ("block", ["block"], {"number": "3"}, "set_block", ("upstairs", ["block"], {"number": "3"}), "no grant gives"),
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
     ("upstairs", ["subnets", "iot", "delete"], {}), "no grant gives"),
    ("ranges", ["ranges"], {"vlan": "20", "kind": "static", "first": "10.1.20.2", "last": "10.1.20.9"}, "add_range",
     ("lan", ["ranges"], {"vlan": "", "kind": "static", "first": "10.1.20.2", "last": "10.1.20.9"}), "1 to 4094"),
    ("ranges.delete", ["ranges", "delete"], {"vlan": "20", "first": "10.1.20.2"}, "remove_range",
     ("lan", ["ranges", "delete"], {"vlan": 20, "first": "10.1.20.2"}), "must be text"),
    ("addresses", ["addresses"], {"ip": "10.1.20.11", "kind": "static", "name": "printer"}, "add_address",
     ("lan", ["addresses"], {"ip": "10.1.20.11", "kind": "static", "dns": "maybe"}), "dns is on or off"),
    ("addresses.*", ["addresses", "10.1.20.10"], {"owner": "office"}, "set_address",
     ("lan", ["addresses", "10.1.20.10"], {"dns": "maybe"}), "dns is on or off"),
    ("addresses.*.delete", ["addresses", "10.1.20.10", "delete"], {}, "remove_address",
     ("upstairs", ["addresses", "10.1.20.10", "delete"], {}), "no grant gives")]
for ident, sub, body, fname, (bad_site, bad_sub, bad_body), words in ROUTES:
    del CALLS[:], APPLIES[:]
    out = m_post.post_networks(["networks", "lan", *sub], "alice", body, caller="alice")
    # covers: agent:post.networks.*.block agent:post.networks.*.vlans agent:post.networks.*.vlans.* +
    # covers: agent:post.networks.*.vlans.*.delete agent:post.networks.*.subnets agent:post.networks.*.subnets.* +
    # covers: agent:post.networks.*.subnets.*.delete agent:post.networks.*.ranges +
    # covers: agent:post.networks.*.ranges.delete agent:post.networks.*.addresses +
    # covers: agent:post.networks.*.addresses.* agent:post.networks.*.addresses.*.delete +
    check(f"POST /v1/networks/<site>/{ident.replace('.', '/')}: {fname}, as the signed-in person (the grant is "
          "checked there), source web; applied unless it is the site's number",
          [c[0] for c in CALLS] == [fname] and CALLS[0][2].get("source") == "web"
          and CALLS[0][2].get("caller") == "alice" and out["own"]
          and (out["applied"] is None) == (sub == ["block"]) and len(APPLIES) == (sub != ["block"]), (CALLS, out))
    del CALLS[:], APPLIES[:]
    # covers: agent:post.networks.*.block agent:post.networks.*.vlans agent:post.networks.*.vlans.* -
    # covers: agent:post.networks.*.vlans.*.delete agent:post.networks.*.subnets agent:post.networks.*.subnets.* -
    # covers: agent:post.networks.*.subnets.*.delete agent:post.networks.*.ranges -
    # covers: agent:post.networks.*.ranges.delete agent:post.networks.*.addresses -
    # covers: agent:post.networks.*.addresses.* agent:post.networks.*.addresses.*.delete -
    check(f"refused: POST /v1/networks/<site>/{ident.replace('.', '/')} ({words}): nothing written or applied",
          refused(lambda: m_post.post_networks(["networks", bad_site, *bad_sub], "alice", bad_body, "alice"),
                  words) is True and not CALLS and not APPLIES, CALLS)
out = m_post.post_networks(["networks", "parents", "vlans"], "alice", {"id": "40", "name": "lab"}, "alice")
check("a change to another site's plan is left to its plan poll, never applied here, saying so",
      out["site"] == "parents" and not out["own"] and out["applied"] is None and "within 30 s" in out["output"]
      and not APPLIES, out)
m_apply.refresh_firewall = lambda: (False, "nft said no")
out = m_post.post_networks(["networks", "lan", "vlans"], "alice", {"id": "40", "name": "lab"}, "alice")
check("this site's change: the firewall failing makes the apply not done, with its output",
      out["applied"] is False and "nft said no" in out["output"], out)
try:
    m_post.post_networks(["networks", "lan", "vlans", "20", "move"], "alice", {}, "alice")
    check("another path under /v1/networks/<site>: 404", False)
except Exception as exc:              # RouteNotFound
    check("another path under /v1/networks/<site>: 404", type(exc).__name__ == "RouteNotFound", exc)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
