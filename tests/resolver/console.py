#!/usr/bin/env python3
"""The DNS filter tab (manual 1.12.2.14, 1.12.3.5, 1.12.3.8) without a host: the settings it changes (lists ticked
and unticked, rules, upstreams, groups) on an in-memory vars file, fabric-agent's routes and their permissions, the
lists job making AdGuard Home match, the web UI's post route and the page for each kind of user. What must be refused
is checked beside what must be accepted.

    python3 tests/resolver/console.py
"""
import contextlib
import copy
import json
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def refused(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except Exception as e:  # noqa: BLE001 — the test reads the refusal's type and text
        return e
    return None


from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.dns_filter.set_filter_list as m_set_list  # noqa: E402
import fabriclib.dns_filter.add_filter_rule as m_add_rule  # noqa: E402
import fabriclib.dns_filter.remove_filter_list as m_rm_list  # noqa: E402
import fabriclib.dns_filter.remove_filter_rule as m_rm_rule  # noqa: E402
import fabriclib.dns_filter.set_filter_upstreams as m_ups  # noqa: E402
import fabriclib.dns_filter.set_filter_group as m_group  # noqa: E402
import fabriclib.dns_filter.remove_filter_group as m_rm_group  # noqa: E402
import fabriclib.dns_filter.set_safe_search as m_safe  # noqa: E402
import fabriclib.dns_filter.refresh_lists as m_refresh  # noqa: E402
from fabriclib.dns_filter.common.list_id import list_id  # noqa: E402
from fabriclib.system.memory_limit_mb import memory_limit_mb  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

L1 = "https://lists.example/one.txt"
BASE = tempfile.mkdtemp()
STORE = {"vars": {"domain": "lan.test", "org_domain": "lan.test", "dns_filter": "bind", "install_resolver": True,
                  "lan_cidr": "192.168.1.0/24", "fabric_subnet": "10.255.0.0/24", "deploy_base_dir": BASE,
                  "adguard_mem_limit": "1024m", "host_ram_capacity": 4, "install_keycloak": True,   # the owner's Pi:
                  # 0.7.0's default limit (counts as not set) and AdGuard Home's share of a 4 GB budget, 429 MiB
                  "dns_filter_lists": [{"name": "One", "url": L1, "enabled": True}], "dns_filter_allow": [],
                  "dns_filter_block": [], "dns_filter_upstreams": [{"address": "1.1.1.1", "name": "cloudflare-dns.com"}]}}
AUDIT = []
for mod in (m_set_list, m_add_rule, m_rm_list, m_rm_rule, m_ups, m_group, m_rm_group, m_safe):
    mod.load_vars = lambda: copy.deepcopy(STORE["vars"])
    mod.save_vars = lambda data: STORE.update(vars=copy.deepcopy(data))
    mod.vars_lock = contextlib.nullcontext
    mod.write_audit = lambda actor, action, detail, source: AUDIT.append((actor, action, detail, source))
v = lambda: STORE["vars"]  # noqa: E731

# ---- lists: ticked, unticked, added from the catalogue or by URL (1.12.3.5)
TWO = "https://lists.example/two.txt"
r = m_set_list.set_filter_list("alice", TWO, True, "Two", "web")
check("add a list: saved after the others, ticked, its id from its URL, audited",
      [i["name"] for i in v()["dns_filter_lists"]] == ["One", "Two"] and v()["dns_filter_lists"][1]["enabled"] is True
      and r["added"] and r["id"] == list_id(TWO) and AUDIT[-1][:2] == ("alice", "DNS_FILTER_LIST_ADD"), (r, AUDIT[-1:]))
r = m_set_list.set_filter_list("alice", TWO, False, "", "web")
check("untick a list: kept on the site, its name kept, audited as off",
      v()["dns_filter_lists"][1] == {"name": "Two", "url": TWO, "enabled": False} and not r["added"]
      and AUDIT[-1][1] == "DNS_FILTER_LIST_OFF", (r, v()["dns_filter_lists"]))
r = m_set_list.set_filter_list("alice", TWO, True, "", "web")
check("tick it again: no second entry", len(v()["dns_filter_lists"]) == 2 and v()["dns_filter_lists"][1]["enabled"]
      and AUDIT[-1][1] == "DNS_FILTER_LIST_ON", v()["dns_filter_lists"])
# a copy whose estimate would take the ticked lists past AdGuard Home's share of the budget (1.12.3.9, 2.1.12.8)
BIG = "https://lists.example/big.txt"
os.makedirs(f"{BASE}/dnsfilter", exist_ok=True)
with open(f"{BASE}/dnsfilter/state.json", "w") as f:
    json.dump({list_id(BIG): {"memory_mb": 500.0}}, f)
before = copy.deepcopy(STORE["vars"])
for args, why in (((("ftp://lists.example/x", True, "x")), "not http(s)"),
                  ((("https://lists.example/y", True, "y" * 201)), "a name over 200 characters"),
                  ((("https://lists.example/nope.txt", False, "")), "unticking a list the site does not have"),
                  (((BIG, True, "Big")), "past AdGuard Home's memory limit")):
    e = refused(m_set_list.set_filter_list, "alice", *args)
    check(f"tick or add a list refused: {why}, saying why, nothing saved",
          isinstance(e, ValidationError) and str(e) and STORE["vars"] == before, e)
_said = str(refused(m_set_list.set_filter_list, "alice", BIG, True, "Big"))
_limit = memory_limit_mb(STORE["vars"], "adguard")       # planned: its share x 2.5 (2.1.12.8)
check("the memory refusal names the estimate, AdGuard Home's share of the budget, its limit and how to make room",
      "about 500 MiB" in _said and f"({_limit / 2.5:.0f} MiB;" in _said and f"{_limit:.0f} MiB while it compiles" in _said
      and "host_ram_capacity" in _said, (_said, _limit))
m_rm_list.remove_filter_list("alice", TWO, "web")
check("remove a list", [i["url"] for i in v()["dns_filter_lists"]] == [L1])
e = refused(m_rm_list.remove_filter_list, "alice", "https://lists.example/nope.txt")
check("remove a list refused: not there", isinstance(e, ValidationError) and "no list" in str(e), e)

# ---- rules
r = m_add_rule.add_filter_rule("alice", "block", "Ads.Example.org.", "web")
check("block a name: normalised (lowercase, no trailing dot), audited",
      v()["dns_filter_block"] == ["ads.example.org"] and r == {"kind": "block", "name": "ads.example.org",
                                                               "moved": False, "group": ""}
      and AUDIT[-1][1] == "DNS_FILTER_BLOCK", r)
r = m_add_rule.add_filter_rule("alice", "allow", "ads.example.org", "web")
check("allowing a blocked name moves it (Allow pressed in the query log)",
      v()["dns_filter_allow"] == ["ads.example.org"] and v()["dns_filter_block"] == [] and r["moved"], r)
m_add_rule.add_filter_rule("alice", "allow", "ads.example.org", "web")
check("allowing it again changes nothing (no duplicate)", v()["dns_filter_allow"] == ["ads.example.org"])
before = copy.deepcopy(STORE["vars"])
for args, why in ((("deny", "x.example"), "another kind"), (("block", "not a name!"), "not a name"),
                  (("block", "nas.lan.test"), "a name inside fabric's own domain")):
    e = refused(m_add_rule.add_filter_rule, "alice", *args)
    check(f"rule refused: {why}, saying why, nothing saved",
          isinstance(e, ValidationError) and str(e) and STORE["vars"] == before, e)
m_rm_rule.remove_filter_rule("alice", "allow", "ADS.example.org", "web")
check("remove a rule (as listed, any case)", v()["dns_filter_allow"] == [])
e = refused(m_rm_rule.remove_filter_rule, "alice", "block", "never.example")
check("remove a rule refused: not in that rule", isinstance(e, ValidationError) and "not blocked" in str(e), e)

# ---- upstreams
r = m_ups.set_filter_upstreams("alice", "9.9.9.9 dns.quad9.net\n149.112.112.112 DNS.quad9.net", "web")
check("upstreams: address and certificate-name pairs, one per line or comma-separated",
      v()["dns_filter_upstreams"] == [{"address": "9.9.9.9", "name": "dns.quad9.net"},
                                      {"address": "149.112.112.112", "name": "dns.quad9.net"}], r)
before = copy.deepcopy(STORE["vars"])
for text, why in (("", "empty"), ("none", "none (AdGuard Home needs one)"),
                  ("9.9.9.9", "an address without its certificate name"),
                  ("dns.quad9.net 9.9.9.9", "the two the wrong way round")):
    e = refused(m_ups.set_filter_upstreams, "alice", text)
    check(f"upstreams refused: {why}, saying why, nothing saved",
          isinstance(e, ValidationError) and str(e) and STORE["vars"] == before, e)

# ---- client groups (1.12.2.15)
r = m_group.set_filter_group("alice", " Kids ", "192.168.1.64/27, 192.168.1.70", "web")
check("add a group: normalised, starts with safe search off and nothing of its own, audited",
      r == {"name": "kids", "clients": ["192.168.1.64/27", "192.168.1.70"], "added": True}
      and v()["dns_filter_groups"][0] == {"name": "kids", "clients": ["192.168.1.64/27", "192.168.1.70"],
                                          "safe_search": False, "youtube": "strict", "allow": [], "block": []} and AUDIT[-1][1] == "DNS_FILTER_GROUP_ADD", (r, v()))
r = m_group.set_filter_group("alice", "kids", ["192.168.1.64/27"], "web")
check("change a group's clients (the rest kept)", not r["added"] and v()["dns_filter_groups"][0]["clients"]
      == ["192.168.1.64/27"] and AUDIT[-1][1] == "DNS_FILTER_GROUP_CLIENTS", r)
before = copy.deepcopy(STORE["vars"])
for args, why in ((("everyone", "192.168.1.5"), "the name everyone"), (("Kid Room", "192.168.1.5"), "a bad name"),
                  (("teen", ""), "no clients"), (("teen", "10.9.9.9"), "outside the networks answered"),
                  (("teen", "10.255.0.40"), "inside fabric's own network"),
                  (("teen", "192.168.1.64/27"), "a subnet another group has")):
    e = refused(m_group.set_filter_group, "alice", *args)
    check(f"group refused: {why}, saying why, nothing saved",
          isinstance(e, ValidationError) and str(e) and STORE["vars"] == before, e)
r = m_add_rule.add_filter_rule("alice", "block", "roblox.com", "web", group="kids")
check("a group's own rule: saved on the group, not on everyone, audited with the group; groups have no lists",
      v()["dns_filter_groups"][0]["block"] == ["roblox.com"] and v()["dns_filter_block"] == []
      and "lists" not in v()["dns_filter_groups"][0] and r["group"] == "kids" and "(group kids)" in AUDIT[-1][2],
      (r, AUDIT[-1:]))
before = copy.deepcopy(STORE["vars"])
for fn, args, why in ((m_add_rule.add_filter_rule, ("block", "x.example", "web", "nosuch"), "a rule for no group"),
                      (m_add_rule.add_filter_rule, ("allow", "lan.test.", "web", "kids"), "a group allow of fabric's zone")):
    e = refused(fn, "alice", *args)
    check(f"group change refused: {why}, saying why, nothing saved",
          isinstance(e, ValidationError) and str(e) and STORE["vars"] == before, e)
r = m_safe.set_safe_search("alice", "kids", "on", "moderate", "web")
check("safe search on for a group, YouTube moderate; everyone's unchanged",
      r == {"group": "kids", "on": True, "youtube": "moderate"} and v()["dns_filter_groups"][0]["safe_search"] is True
      and v()["dns_filter_groups"][0]["youtube"] == "moderate" and not v().get("dns_filter_safe_search"), r)
r = m_safe.set_safe_search("alice", "", True, "strict", "web")
check("safe search for everyone", r["group"] == "" and v()["dns_filter_safe_search"] is True
      and AUDIT[-1][2] == "everyone: strict, YouTube strict", AUDIT[-1:])
m_safe.set_safe_search("alice", "", "", "strict", "web")
check("an unchecked box is off", v()["dns_filter_safe_search"] is False)
before = copy.deepcopy(STORE["vars"])
for args, why in ((("kids", True, "off"), "a YouTube level other than strict or moderate"),
                  (("nosuch", True, "strict"), "an unknown group")):
    e = refused(m_safe.set_safe_search, "alice", *args)
    check(f"safe search refused: {why}, saying why, nothing saved",
          isinstance(e, ValidationError) and str(e) and STORE["vars"] == before, e)
m_rm_group.remove_filter_group("alice", "KIDS", "web")
check("remove a group (any case), audited", v()["dns_filter_groups"] == [] and AUDIT[-1][1] == "DNS_FILTER_GROUP_REMOVE")
e = refused(m_rm_group.remove_filter_group, "alice", "kids")
check("remove a group refused: not there", isinstance(e, ValidationError) and "no client group" in str(e), e)

# ---- fabric-agent's routes and their permissions
routes = {("GET", ("dns-filter",)): "dns:filter", ("POST", ("dns-filter", "querylog")): "dns:querylog"}
routes.update({("POST", ("dns-filter", *p)): "dns:filter"
               for p in (("lists",), ("lists", "set"), ("lists", "delete"), ("rules",), ("rules", "delete"), ("upstreams",), ("fetch",),
                         ("groups",), ("groups", "delete"), ("safe-search",))})
check("every route needs its permission: the query log dns:querylog, the rest dns:filter",
      all(required_permission(m, list(p)) == need for (m, p), need in routes.items()))
check("refused: a DNS filter route not listed (default deny)",
      required_permission("POST", ["dns-filter", "lists", "rename"]) is None
      and required_permission("GET", ["dns-filter", "querylog"]) is None)
check("network operators manage the filter but cannot read the query log; auditors neither",
      "dns:filter" in BUNDLES["fabric-network-operator"] and "dns:querylog" not in BUNDLES["fabric-network-operator"]
      and not {"dns:filter", "dns:querylog"} & set(BUNDLES["fabric-auditor"]))

import agent.post_dns_filter as pdf  # noqa: E402
from agent.route_not_found import RouteNotFound  # noqa: E402
CALLS, HAVE, WAIT = [], [], {"why": None}
pdf.apply_dns_filter = lambda actor, source: (CALLS.append(("apply", actor, source)) or {"waiting": WAIT["why"]})
pdf.start_list_fetch = lambda: (CALLS.append(("fetch",)) or True)
pdf.adguard_desired = lambda vv: {"filters": [{"source": u} for u in HAVE]}     # the lists with a copy
pdf.set_filter_list = m_set_list.set_filter_list
pdf.load_vars = lambda: STORE["vars"]
pdf.read_query_log = lambda vv, **kw: (CALLS.append(("querylog", kw)) or {"entries": []})
r = pdf.post_dns_filter(["dns-filter", "lists"], "alice", {"name": "Three", "url": "https://lists.example/3.txt"})
# covers: agent:post.dns-filter.lists +
check("agent: a list added with no copy yet is saved, made at once, and the lists job starts (no internet here)",
      r["applied"] and r["fetching"] and CALLS[-2:] == [("apply", "alice", "web"), ("fetch",)], (r, CALLS))


def _no_job():
    raise ValidationError("the lists job could not start: Unit fabric-dns-lists.service not found.")


pdf.start_list_fetch = _no_job
r = pdf.post_dns_filter(["dns-filter", "lists"], "alice", {"name": "Four", "url": "https://lists.example/4.txt"})
pdf.start_list_fetch = lambda: (CALLS.append(("fetch",)) or True)
check("agent: a list added while the lists job cannot start is saved and says what waits (not a refusal)",
      not r["applied"] and not r["fetching"] and "could not start" in r["waiting"]
      and "fabricctl dns-filter lists" in r["waiting"]
      and any(x["url"] == "https://lists.example/4.txt" for x in STORE["vars"]["dns_filter_lists"]), r)
CALLS.clear()
HAVE.append(L1)
r = pdf.post_dns_filter(["dns-filter", "lists", "set"], "alice", {"url": L1, "enabled": "off"})
r2 = pdf.post_dns_filter(["dns-filter", "lists", "set"], "alice", {"url": L1, "enabled": "on"})
# covers: agent:post.dns-filter.lists.set +
check("agent: untick and tick a list with a copy: each made at once, nothing fetched",
      r["result"]["enabled"] is False and r2["result"]["enabled"] is True and not r2["fetching"]
      and CALLS == [("apply", "alice", "web")] * 2, (r, r2, CALLS))
CALLS.clear()
WAIT["why"] = "AdGuard Home is not answering"
r = pdf.post_dns_filter(["dns-filter", "lists", "set"], "alice", {"url": L1, "enabled": "off"})
check("agent: AdGuard not answering: the change is saved and says it waits", not r["applied"]
      and r["waiting"] == WAIT["why"] and v()["dns_filter_lists"][0]["enabled"] is False, r)
WAIT["why"] = None
CALLS.clear()
for body, why in (({"url": "ftp://x"}, "not http(s)"), ({"url": L1, "enabled": "maybe"}, "a tick that is not on or off")):
    e = refused(pdf.post_dns_filter, ["dns-filter", "lists", "set"], "alice", body)
    # covers: agent:post.dns-filter.lists.set -
    check(f"agent: refused ({why}) is a 400 (ValidationError), nothing applied or fetched",
          isinstance(e, ValidationError) and CALLS == [], (e, CALLS))
CALLS.clear()
e = refused(pdf.post_dns_filter, ["dns-filter", "lists"], "alice", {"url": "ftp://x"})
# covers: agent:post.dns-filter.lists -
check("agent: a refused new list is a 400 (ValidationError) and nothing is applied or fetched",
      isinstance(e, ValidationError) and CALLS == [], (e, CALLS))
e = refused(pdf.post_dns_filter, ["dns-filter", "lists"], "alice", {"url": 42})
check("agent: a field that is not text is refused", isinstance(e, ValidationError) and "text" in str(e), e)
check("agent: an unknown DNS filter route is a 404", isinstance(refused(pdf.post_dns_filter, ["dns-filter", "x"],
                                                                         "alice", {}), RouteNotFound))
pdf.set_filter_group, pdf.remove_filter_group = m_group.set_filter_group, m_rm_group.remove_filter_group
pdf.set_safe_search, pdf.add_filter_rule = m_safe.set_safe_search, m_add_rule.add_filter_rule
CALLS.clear()
r = pdf.post_dns_filter(["dns-filter", "groups"], "alice", {"name": "guests", "clients": "192.168.1.200"})
r2 = pdf.post_dns_filter(["dns-filter", "safe-search"], "alice", {"group": "guests", "on": "on", "youtube": "moderate"})
r3 = pdf.post_dns_filter(["dns-filter", "rules"], "alice", {"group": "guests", "kind": "block", "name": "x.example"})
# covers: agent:post.dns-filter.groups agent:post.dns-filter.safe-search agent:post.dns-filter.rules +
check("agent: a group added, its safe search and its rule — each saved and applied, nothing fetched",
      r["result"]["added"] and r2["result"]["youtube"] == "moderate" and r3["result"]["group"] == "guests"
      and not r["fetching"] and CALLS == [("apply", "alice", "web")] * 3, (r, r2, r3, CALLS))
r = pdf.post_dns_filter(["dns-filter", "groups", "delete"], "alice", {"name": "guests"})
# covers: agent:post.dns-filter.groups.delete +
check("agent: a group removed", r["result"]["name"] == "guests" and v()["dns_filter_groups"] == [], r)
e = refused(pdf.post_dns_filter, ["dns-filter", "groups"], "alice", {"name": "x", "clients": ["192.168.1.9"]})
# covers: agent:post.dns-filter.groups -
check("agent: clients sent as a list (not text) are refused", isinstance(e, ValidationError) and "text" in str(e), e)
r = pdf.post_dns_filter(["dns-filter", "querylog"], "alice", {"client": "192.168.1.0/24", "blocked": True, "limit": 50})
check("agent: the query-log search passes its terms on", CALLS[-1] == ("querylog", {
    "client": "192.168.1.0/24", "name": "", "blocked_only": True, "limit": 50}), CALLS[-1:])

# ---- the lists job: copies fetched, then AdGuard made to match and asked to reread what changed (1.12.3.5)
with tempfile.TemporaryDirectory() as tmp:
    vv = {"deploy_base_dir": tmp, "dns_filter_lists": [{"name": "One", "url": L1}]}
    API, SYNC = [], {"fail": None}
    m_refresh.fetch_catalogue = lambda vv: {"lists": [1, 2, 3]}
    m_refresh.update_lists = lambda vv, catalogue=(): {"changed": [L1], "failed": [], "lists": {}}

    def fake_sync(vv, pw):
        if SYNC["fail"]:
            raise ValidationError(SYNC["fail"])
        return ["list added: One"]

    m_refresh.sync_adguard = fake_sync
    m_refresh.adguard_api = lambda vv, pw, method, path, body=None, timeout=30: API.append(path)
    r = m_refresh.refresh_lists(vv, "pw")
    check("lists job: a changed copy: AdGuard synced, then asked to reread its lists",
          r["catalogue"] == 3 and r["synced"] == ["list added: One"] and API == ["/control/filtering/refresh"]
          and r["error"] is None, (r, API))
    API.clear()
    m_refresh.update_lists = lambda vv, catalogue=(): {"changed": [], "failed": [], "lists": {}}
    r = m_refresh.refresh_lists(vv, "pw")
    check("lists job: nothing changed, nothing reread", API == [] and r["synced"] == ["list added: One"], (r, API))
    os.makedirs(f"{tmp}/dnsfilter")
    with open(f"{tmp}/dnsfilter/catalogue.json", "w") as f:
        json.dump({"fetched": 1, "lists": [{"name": "Kept", "url": "https://x/kept"}]}, f)
    SEEN = []
    m_refresh.update_lists = lambda vv, catalogue=(): (SEEN.append(list(catalogue)) or
                                                       {"changed": [], "failed": [], "lists": {}})
    m_refresh.fetch_catalogue = lambda vv: (_ for _ in ()).throw(OSError("offline"))
    SYNC["fail"] = "AdGuard Home is not answering"
    r = m_refresh.refresh_lists(vv, "pw")
    check("lists job: the catalogue unreachable uses its last copy (None); AdGuard down is reported, not raised",
          r["catalogue"] is None and SEEN == [[{"name": "Kept", "url": "https://x/kept"}]]
          and r["synced"] is None and "not answering" in r["error"], (r, SEEN))

# ---- the web UI: its post route and the page for each kind of user
from webui import views  # noqa: E402
import webui.routes.dns_filter_post as wpost  # noqa: E402
from fabriclib.rbac.required_permission import POST as AGENT_POST  # noqa: E402
from webui.agentclient.dns_filter_change import CHANGES  # noqa: E402

# every change the tab posts is one the console sends on, and one the agent serves (2.3.1.16: groups, groups/delete and
# safe-search were missing from CHANGES, so those forms answered 500; the stand-in agent below accepts anything)
check("web: every change the DNS filter tab posts is in the console's list of changes (none answers 500)",
      set(wpost.BACK) <= CHANGES, sorted(set(wpost.BACK) - CHANGES))
check("web: ...and each is a route the agent serves (its permission table)",
      all(("dns-filter", *what.split("/")) in AGENT_POST for what in CHANGES), sorted(CHANGES))


class H:
    def __init__(self):
        self.out = None

    def redirect(self, location, headers=None):
        self.out = (303, location)

    def deny(self, status, text):
        self.out = (status, text)


class FakeActions:
    ValidationError = ValidationError

    def __init__(self, applied=True, refuse=None):
        self.applied, self.refuse, self.calls = applied, refuse, []

    def dns_filter_change(self, what, body):
        self.calls.append((what, body))
        if self.refuse:
            raise ValidationError(self.refuse)
        result = [{"address": "9.9.9.9", "name": "dns.quad9.net"}] if what == "upstreams" else \
            {"name": body.get("name"), "kind": body.get("kind")}          # the agent's shapes
        return {"result": result, "applied": self.applied, "fetching": True,
                "waiting": None if self.applied else "AdGuard Home is not answering"}


h, wpost.actions = H(), FakeActions()
wpost.dns_filter_post(h, ["rules"], {"kind": "block", "name": "x.example", "back": "querylog"})
# covers: web:post.dns-filter.rules +
check("web: Block from the query log saves and goes back to the query log with the outcome",
      h.out[0] == 303 and h.out[1].startswith("/dns-filter?view=querylog&msg=") and wpost.actions.calls[-1][0] == "rules",
      h.out)
wpost.dns_filter_post(h, ["lists"], {"name": "Two", "url": "https://x/2", "back": "<script>"})
# covers: web:post.dns-filter.lists +
check("web: a back section that is not one is ignored (the change's own section)",
      h.out[1].startswith("/dns-filter?view=lists&msg="), h.out)
wpost.dns_filter_post(h, ["lists", "set"], {"url": "https://x/2", "name": "Two", "enabled": "off"})
# covers: web:post.dns-filter.lists.set +
check("web: a tick posts the list's URL and on or off, and goes back to Lists",
      wpost.actions.calls[-1] == ("lists/set", {"name": "Two", "url": "https://x/2", "enabled": "off", "kind": "",
                                                "upstreams": "", "group": "", "clients": "", "on": "", "youtube": ""})
      and h.out[1].startswith("/dns-filter?view=lists&msg="), (wpost.actions.calls[-1:], h.out))
h, wpost.actions = H(), FakeActions(refuse="not a DNS name")
wpost.dns_filter_post(h, ["rules"], {"kind": "block", "name": "bad!"})
check("web: a refused change goes back with the reason (err)", "err=not+a+DNS+name" in h.out[1], h.out)
h, wpost.actions = H(), FakeActions(refuse="a tick that is not on or off")
wpost.dns_filter_post(h, ["lists", "set"], {"url": "https://x/2", "enabled": "maybe", "back": "lists"})
# covers: web:post.dns-filter.lists.set -
check("web: a refused tick goes back to Lists with the reason (err)",
      "err=a+tick+that+is+not+on+or+off" in h.out[1] and "view=lists" in h.out[1], h.out)
h, wpost.actions = H(), FakeActions(applied=False)
wpost.dns_filter_post(h, ["upstreams"], {"upstreams": "9.9.9.9 dns.quad9.net"})
check("web: saved but waiting says so, with why",
      "Saved%2C+but+not+in+use+yet" in h.out[1] and "not+answering" in h.out[1] and "view=settings" in h.out[1], h.out)
h = H()
wpost.dns_filter_post(h, ["lists", "rename"], {})
check("web: an unknown change is a 404", h.out[0] == 404, h.out)
h, wpost.actions = H(), FakeActions()
wpost.dns_filter_post(h, ["safe-search"], {"group": "kids", "youtube": "strict", "back": "groups"})
# covers: web:post.dns-filter.safe-search +
check("web: safe search with the box unchecked sends on='' (off) for its group, and goes back to Groups",
      wpost.actions.calls[-1] == ("safe-search", {"name": "", "url": "", "enabled": "", "kind": "", "upstreams": "",
                                                  "group": "kids", "clients": "", "on": "", "youtube": "strict"})
      and h.out[1].startswith("/dns-filter?view=groups&msg="), (wpost.actions.calls[-1:], h.out))
wpost.dns_filter_post(h, ["groups"], {"name": "kids", "clients": "192.168.1.64/27"})
# covers: web:post.dns-filter.groups +
check("web: a group's change goes back to Groups", h.out[1].startswith("/dns-filter?view=groups&msg="), h.out)

from fabriclib.dns_filter.common.safe_search import safe_search_summary  # noqa: E402
from webui.devpreview.sample_data import SAMPLE_DNS_FILTER  # noqa: E402
OV = {**copy.deepcopy(SAMPLE_DNS_FILTER), "safe_search_sites": safe_search_summary(),
      "stats": {"off": "Postgres is not installed"}}
LOG = {"entries": [{"at": "2026-10-09T10:00:00Z", "client": "192.168.1.2", "view": "everyone", "name": "ads.example",
                    "qtype": "A", "action": "NXDOMAIN", "zone": "owner.rpz", "list": None, "blocked": True},
                   {"at": "2026-10-09T10:00:01Z", "client": "192.168.1.66", "view": "kids", "name": "roblox.com",
                    "qtype": "A", "action": "NXDOMAIN", "zone": "group-kids.rpz", "list": None, "blocked": True}]}
SEARCH = {"client": "", "name": "", "blocked": "", "limit": ""}


def ctx(*perms):
    return {"perms": list(perms), "csrf": "t", "user": "alice", "dev": False,
            "version": {"version": "test", "build": ""}}


admin = views.dns_filter(ctx("dns:filter", "dns:querylog"), "querylog", OV, LOG, SEARCH)
operator = views.dns_filter(ctx("dns:filter"), "rules", OV, None, SEARCH)
reader = views.dns_filter(ctx("dns:querylog"), "querylog", None, LOG, SEARCH)
check("page: the admin sees the query log with Allow on a blocked line, and the DNS filter tab",
      "ads.example" in admin and 'action="/dns-filter/rules"' in admin and 'href="/dns-filter"' in admin)
check("page: a network operator gets the rules' forms but no Query log section",
      'action="/dns-filter/rules"' in operator and "?view=querylog" not in operator)
check("page: with dns:querylog only, the log shows without any form that changes the filter",
      "ads.example" in reader and "/dns-filter/rules" not in reader and "/dns-filter/lists" not in reader)
check("page: statistics off says why", "Postgres is not installed" in views.dns_filter(
    ctx("dns:filter"), "overview", OV, None, SEARCH))
check("page: Allow on a group's blocked line goes to that group's rules",
      'name="group" value="kids"' in admin and "the group&#39;s rules" in admin, admin[admin.find("roblox"):][:600])
groups = views.dns_filter(ctx("dns:filter"), "groups", OV, None, SEARCH)
check("page: Groups names every engine strict safe search covers, from fabric's own table, and what it cannot",
      all(f"{e['engine']} ({e['names']} " in groups for e in safe_search_summary()["engines"])
      and "Brave Search" in groups and 'value="moderate" selected' in groups, groups[:300])
lists = views.dns_filter(ctx("dns:filter"), "lists", OV, None, SEARCH)
check("page: every list a checkbox posting its tick, by category, with its memory and the limit",
      lists.count('action="/dns-filter/lists/set"') == len(OV["lists"]) and 'aria-pressed="true"' in lists
      and "Security" in lists and "~24.5 MiB" in lists and "of a limit of 1024 MiB" in lists, lists[:400])
check("page: only a list added by URL has Remove", lists.count('action="/dns-filter/lists/delete"') == 1)
seen = views.dns_filter(ctx("dns:querylog"), "lists", OV, LOG, SEARCH)
check("page: without dns:filter the ticks show but post nothing", "/dns-filter/lists/set" not in seen
      and 'class="tick on"' in seen)
check("page: everyone's safe search is in Settings",
      'action="/dns-filter/safe-search"' in views.dns_filter(ctx("dns:filter"), "settings", OV, None, SEARCH))
viewer = views.dns_filter(ctx("dns:querylog"), "groups", None, LOG, SEARCH)
check("page: without dns:filter no group form shows", "/dns-filter/groups" not in viewer
      and "/dns-filter/safe-search" not in viewer)

print("\nall passed (0 failures)" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
