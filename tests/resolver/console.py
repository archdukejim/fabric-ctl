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
import urllib.parse
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
                  "host_ram_capacity": 4, "install_keycloak": True,   # the owner's Pi: AdGuard Home's share of a
                  # 4 GB budget, 429 MiB
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

import fabriclib.dns_filter.set_filter_lists as m_set_lists  # noqa: E402
m_set_lists.load_vars = lambda: copy.deepcopy(STORE["vars"])
m_set_lists.save_vars = lambda data: STORE.update(vars=copy.deepcopy(data))
m_set_lists.vars_lock = contextlib.nullcontext
m_set_lists.write_audit = lambda actor, action, detail, source: AUDIT.append((actor, action, detail, source))
import agent.apply_filter_now as afn  # noqa: E402
import agent.post_dns_filter as pdf  # noqa: E402
from agent.route_not_found import RouteNotFound  # noqa: E402
CALLS, HAVE, WAIT = [], [], {"why": None}
afn.apply_dns_filter = lambda actor, source: (CALLS.append(("apply", actor, source)) or {"waiting": WAIT["why"]})
afn.start_list_fetch = lambda: (CALLS.append(("fetch",)) or True)
afn.adguard_desired = lambda vv: {"filters": [{"source": u} for u in HAVE]}     # the lists with a copy
afn.load_vars = lambda: STORE["vars"]
pdf.load_vars = lambda: STORE["vars"]
pdf.read_query_log = lambda vv, **kw: (CALLS.append(("querylog", kw)) or {"entries": []})
r = pdf.post_dns_filter(["dns-filter", "lists"], "alice", {"name": "Three", "url": "https://lists.example/3.txt"})
# covers: agent:post.dns-filter.lists +
check("agent: a list added with no copy yet is saved, made at once, and the lists job starts (no internet here)",
      r["applied"] and r["fetching"] and CALLS[-2:] == [("apply", "alice", "web"), ("fetch",)], (r, CALLS))


def _no_job():
    raise ValidationError("the lists job could not start: Unit fabric-dns-lists.service not found.")


afn.start_list_fetch = _no_job
r = pdf.post_dns_filter(["dns-filter", "lists"], "alice", {"name": "Four", "url": "https://lists.example/4.txt"})
afn.start_list_fetch = lambda: (CALLS.append(("fetch",)) or True)
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
CALLS.clear()
r = pdf.post_dns_filter(["dns-filter", "groups"], "alice", {"name": "guests", "clients": "192.168.1.200"})
r2 = pdf.post_dns_filter(["dns-filter", "safe-search"], "alice", {"group": "guests", "on": "on", "youtube": "moderate"})
r3 = pdf.post_dns_filter(["dns-filter", "rules"], "alice", {"group": "guests", "kind": "block", "name": "x.example"})
# covers: agent:post.dns-filter.groups agent:post.dns-filter.safe-search agent:post.dns-filter.rules +
check("agent: a group added, its safe search and its rule — each saved and applied, nothing fetched",
      r["result"]["added"] and r2["result"]["youtube"] == "moderate" and r3["result"]["group"] == "guests"
      and not r["fetching"] and CALLS == [("apply", "alice", "web")] * 3, (r, r2, r3, CALLS))
r = pdf.post_dns_filter(["dns-filter", "safe-search"], "alice", {"group": "guests", "youtube": "moderate"})
g = [x for x in v()["dns_filter_groups"] if x["name"] == "guests"][0]
check("agent: safe search turned off keeps the YouTube level the form sends (the page's hidden copy)",
      r["result"] == {"group": "guests", "on": False, "youtube": "moderate"}
      and g.get("safe_search") is False and g.get("youtube") == "moderate", (r, g))
r = pdf.post_dns_filter(["dns-filter", "groups", "delete"], "alice", {"name": "guests"})
# covers: agent:post.dns-filter.groups.delete +
check("agent: a group removed", r["result"]["name"] == "guests" and v()["dns_filter_groups"] == [], r)
e = refused(pdf.post_dns_filter, ["dns-filter", "groups"], "alice", {"name": "x", "clients": ["192.168.1.9"]})
# covers: agent:post.dns-filter.groups -
check("agent: clients sent as a list (not text) are refused", isinstance(e, ValidationError) and "text" in str(e), e)
r = pdf.post_dns_filter(["dns-filter", "querylog"], "alice", {"client": "192.168.1.0/24", "blocked": True, "limit": 50})
# covers: agent:post.dns-filter.querylog +
check("agent: the query-log search passes its terms on (fabric's own hidden unless asked: own False)",
      CALLS[-1] == ("querylog", {"client": "192.168.1.0/24", "name": "", "blocked_only": True, "limit": 50,
                                 "own": False}), CALLS[-1:])
pdf.post_dns_filter(["dns-filter", "querylog"], "alice", {"own": True})
check("agent: own true (fabric's own queries too, 2.1.12.12) is passed on", CALLS[-1][1]["own"] is True, CALLS[-1:])
from fabriclib.dns_filter.read_query_log import read_query_log as real_read_query_log  # noqa: E402
pdf.read_query_log = real_read_query_log         # refused before the log is read: no Postgres needed
for bad in ("yes", 1, None):
    e = refused(pdf.post_dns_filter, ["dns-filter", "querylog"], "alice", {"own": bad})
    # covers: agent:post.dns-filter.querylog -
    check(f"agent: own {bad!r} (not a JSON boolean) refused, saying why",
          isinstance(e, ValidationError) and "true or false" in str(e), e)
pdf.read_query_log = lambda vv, **kw: (CALLS.append(("querylog", kw)) or {"entries": []})

# ---- the lists form's ticks called directly: one save, the whole set's memory (1.12.3.17)
FIVE = "https://lists.example/5.txt"
STORE["vars"]["dns_filter_lists"] = [{"name": "One", "url": L1, "enabled": False},
                                     {"name": "Two", "url": TWO, "enabled": True}]
CALLS.clear()
n_audit = len(AUDIT)
r = pdf.post_dns_filter(["dns-filter", "lists", "ticks"], "alice",
                        {"tick": [{"url": L1, "name": "One"}, {"url": FIVE, "name": "Five"}],
                         "untick": [{"url": TWO, "name": "Two"}]})
# covers: agent:post.dns-filter.lists.ticks +
check("agent: every tick at once: one save, one audit, one apply; a list new to the site added, unticked kept",
      [(i["url"], i["enabled"]) for i in v()["dns_filter_lists"]] == [(L1, True), (TWO, False), (FIVE, True)]
      and r["result"]["ticked"] == ["One", "Five"] and r["result"]["unticked"] == ["Two"]
      and r["result"]["added"] == ["Five"] and len(AUDIT) == n_audit + 1 and AUDIT[-1][1] == "DNS_FILTER_LISTS"
      and CALLS == [("apply", "alice", "web"), ("fetch",)], (r, CALLS, AUDIT[n_audit:]))
before = copy.deepcopy(STORE["vars"])
CALLS.clear()
for body, why in (({"tick": "x"}, "tick not a list"), ({"tick": [{"url": 3}]}, "a URL that is not text"),
                  ({"tick": [{"url": L1}], "untick": [{"url": L1}]}, "a list ticked and unticked at once"),
                  ({"untick": [{"url": "https://lists.example/nope.txt"}]}, "unticking a list the site does not have"),
                  ({"tick": [{"url": "ftp://lists.example/x", "name": "x"}]}, "not http(s)"),
                  ({"tick": [{"url": BIG, "name": "Big"}]}, "the whole set past AdGuard Home's memory limit")):
    e = refused(pdf.post_dns_filter, ["dns-filter", "lists", "ticks"], "alice", body)
    # covers: agent:post.dns-filter.lists.ticks -
    check(f"agent: ticks refused ({why}), saying why; nothing saved, applied or fetched",
          isinstance(e, ValidationError) and str(e) and STORE["vars"] == before and CALLS == [], (e, CALLS))
_said = str(refused(pdf.post_dns_filter, ["dns-filter", "lists", "ticks"], "alice",
                    {"tick": [{"url": BIG, "name": "Big"}]}))
check("agent: the memory refusal names the list ticked with its estimate, the gap past the limit, and how to make "
      "room; nothing was changed",
      "Big (~500 MiB)" in _said and "MiB past its limit of" in _said and "untick about" in _said
      and "host_ram_capacity" in _said and "Nothing was changed" in _said, _said)

# ---- the tab's Apply (1.12.3.17, 2.1.12.14): every change held by fabric-agent, one Apply makes them all
import agent.post_pending as pp  # noqa: E402
from agent.pending_filter import HELD  # noqa: E402
from agent.pending_store import PendingStore  # noqa: E402
from agent.pending_thing import thing_state, pending_page_of  # noqa: E402
from fabriclib.dns_filter.common.lists_version import lists_version  # noqa: E402
from fabriclib.dns_filter.filter_lists import filter_lists  # noqa: E402
JOB = {}


def _sync_job(kind, owner, fn):
    JOB["result"] = fn()                     # the store's apply job, run at once
    return {"id": "job-1"}


pp.PENDING = PendingStore(run=pp._run, state=lambda route, body: thing_state(route, body, STORE["vars"]),
                          need=lambda route: required_permission("POST", route), start_job=_sync_job,
                          finish=pp._finish, check=lambda owner, route, body: pp.filter_check(owner, route, body))
pp.load_vars = lambda: STORE["vars"]
pp.write_audit = lambda actor, action, detail, source: AUDIT.append((actor, action, detail, source))
PERMS = set(BUNDLES["fabric-network-operator"])
check("the DNS filter's changes are held on its own page; the search and the fetch are done at once",
      all(pending_page_of(["dns-filter", *w.split("/")]) == "dns-filter" for w in HELD)
      and pending_page_of(["dns-filter", "querylog"]) is None and pending_page_of(["dns-filter", "fetch"]) is None)


def hold(what, body):
    return pp.post_pending(["pending", "hold"], "alice", {"route": f"dns-filter/{what}", "body": body}, PERMS, None)


def page_form(ticked_urls):
    """The lists form as the page sends it: every list shown, the boxes ticked, the page's version."""
    rows = filter_lists(STORE["vars"])["lists"]
    return {"on": [r["id"] for r in rows if r["url"] in ticked_urls], "shown": [r["id"] for r in rows],
            "version": lists_version(rows)}


STORE["vars"]["dns_filter_lists"] = [{"name": "One", "url": L1, "enabled": True},
                                     {"name": "Two", "url": TWO, "enabled": False}]
STORE["vars"]["dns_filter_block"] = []
STORE["vars"]["dns_filter_upstreams"] = [{"address": "1.1.1.1", "name": "cloudflare-dns.com"}]
CALLS.clear()
saved = copy.deepcopy(STORE["vars"])
r1 = hold("lists/ticks", page_form({TWO}))           # One unticked, Two ticked
r2 = hold("rules", {"kind": "block", "name": "ads.example"})
r3 = hold("upstreams", {"upstreams": "9.9.9.9 dns.quad9.net"})
# covers: agent:post.pending.hold +
check("Apply: a tick, a rule and the upstreams change nothing until Apply (held: nothing saved, nothing applied)",
      STORE["vars"] == saved and CALLS == [] and r3["pending"] == 3 and r1["page"] == "dns-filter"
      and r1["what"] == "Tick Two; untick One", (r1, r2, r3, CALLS))
review = pp.PENDING.page("alice", "dns-filter", lambda p: True)
check("Apply: the Review lists each change waiting, the ticks as the lists that differ",
      [c["what"] for c in review["changes"]] == ["Tick Two; untick One", "Block ads.example",
                                                  "Set the upstreams to 9.9.9.9, dns.quad9.net"]
      and review["changes"][0]["new"] == {"tick": [{"url": TWO, "name": "Two"}], "untick": [{"url": L1, "name": "One"}]},
      review["changes"])
n_audit = len(AUDIT)
pp.post_pending(["pending", "dns-filter", "apply"], "alice", {}, PERMS, None)
check("Apply: one Apply makes every waiting change: each saved, the filter applied once, the list ticked with no "
      "copy fetched once",
      [(i["url"], i["enabled"]) for i in v()["dns_filter_lists"]] == [(L1, False), (TWO, True)]
      and v()["dns_filter_block"] == ["ads.example"] and v()["dns_filter_upstreams"][0]["address"] == "9.9.9.9"
      and CALLS == [("apply", "alice", "web"), ("fetch",)] and JOB["result"]["applied"] == 3
      and [i["state"] for i in JOB["result"]["items"]] == ["done"] * 4
      and pp.PENDING.counts("alice", lambda p: True) == {} and AUDIT[-1][1] == "PENDING_APPLY",
      (JOB, CALLS, v()["dns_filter_lists"]))
check("Apply: its last step says the first copy is being fetched",
      "first copy" in JOB["result"]["items"][-1]["why"], JOB["result"]["items"][-1])

# Discard drops every change waiting; nothing saved
CALLS.clear()
saved = copy.deepcopy(STORE["vars"])
hold("lists/ticks", page_form({L1, TWO}))
hold("rules/delete", {"kind": "block", "name": "ads.example"})
out = pp.post_pending(["pending", "dns-filter", "discard"], "alice", {}, PERMS, None)
check("Discard: drops the tab's waiting changes; nothing saved or applied",
      out == {"dropped": 2, "pending": 0} and STORE["vars"] == saved and CALLS == [], (out, CALLS))

# the memory rule over the whole set: refused at hold, nothing held or changed
with open(f"{BASE}/dnsfilter/state.json", "w") as f:
    json.dump({list_id(L1): {"memory_mb": 250.0}, list_id(TWO): {"memory_mb": 250.0}}, f)
saved = copy.deepcopy(STORE["vars"])
e = refused(hold, "lists/ticks", page_form({L1, TWO}))
check("Apply: ticks that together pass AdGuard Home's limit are refused at once, naming the list and the gap; "
      "nothing held, nothing changed",
      isinstance(e, ValidationError) and "One (~250 MiB)" in str(e) and "past its limit" in str(e)
      and STORE["vars"] == saved and pp.PENDING.counts("alice", lambda p: True) == {} and CALLS == [], e)
os.remove(f"{BASE}/dnsfilter/state.json")

# a stale page: the lists changed after the page was shown
old_form = page_form({L1, TWO})
m_set_list.set_filter_list("bob", L1, True, "", "cli")              # someone else ticks One meanwhile
saved = copy.deepcopy(STORE["vars"])
e = refused(hold, "lists/ticks", old_form)
# covers: agent:post.pending.hold -
check("Apply: a page whose lists changed since it was shown is refused, saying why; nothing held or changed",
      isinstance(e, ValidationError) and "changed since this page was shown" in str(e)
      and STORE["vars"] == saved and pp.PENDING.counts("alice", lambda p: True) == {}, e)
for body, why in (({"on": "x", "shown": [], "version": ""}, "on not a list"),
                  ({"on": ["nope"], "shown": [], "version": old_form["version"]}, "a box the page did not show")):
    e = refused(hold, "lists/ticks", body)
    check(f"Apply: a malformed lists form refused ({why})", isinstance(e, ValidationError) and str(e), e)
r = hold("lists/ticks", page_form({L1, TWO}))
check("Apply: the lists form with no box changed holds nothing", r["id"] is None and r["pending"] == 0, r)

# a bad change is refused when held (fabriclib's own check), not at Apply
e = refused(hold, "rules", {"kind": "block", "name": "not a name!"})
check("Apply: a rule fabriclib refuses is refused when held, saying why; nothing waits",
      isinstance(e, ValidationError) and str(e) and pp.PENDING.counts("alice", lambda p: True) == {}, e)
e = refused(hold, "groups", {"name": "teen", "clients": "10.9.9.9"})
check("Apply: a group outside the networks answered is refused when held", isinstance(e, ValidationError), e)

# a held change whose part of the filter changed before Apply is refused at Apply and stays
CALLS.clear()
hold("upstreams", {"upstreams": "1.1.1.1 cloudflare-dns.com"})
m_ups.set_filter_upstreams("bob", "8.8.8.8 dns.google", "cli")
pp.post_pending(["pending", "dns-filter", "apply"], "alice", {}, PERMS, None)
check("Apply: a change whose part changed since (another person) is refused at Apply and stays waiting; nothing "
      "applied",
      JOB["result"]["items"][0]["state"] == "failed" and "changed since" in JOB["result"]["items"][0]["why"]
      and v()["dns_filter_upstreams"][0]["address"] == "8.8.8.8" and CALLS == []
      and pp.PENDING.counts("alice", lambda p: True)["dns-filter"]["pending"] == 1, (JOB, CALLS))
pp.post_pending(["pending", "dns-filter", "discard"], "alice", {}, PERMS, None)
e = refused(pp.post_pending, ["pending", "dns-filter", "apply"], "alice", {}, PERMS, None)
check("Apply: with nothing waiting it is refused, saying so", isinstance(e, ValidationError)
      and "nothing is pending" in str(e), e)
STORE["vars"]["dns_filter_upstreams"] = [{"address": "1.1.1.1", "name": "cloudflare-dns.com"}]

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
import webui.routes.held as wheld  # noqa: E402
from fabriclib.rbac.required_permission import POST as AGENT_POST  # noqa: E402

# every change the tab holds is one fabric-agent holds on the DNS filter's page and serves (2.3.1.16: groups,
# groups/delete and safe-search were once missing, so those forms answered 500)
HELD_WEB = (set(wpost.BACK) - {"fetch", "lists/apply"}) | {"lists/ticks"}
check("web: every change the DNS filter tab holds is held by fabric-agent on the tab's page, and served",
      all(("dns-filter", *w.split("/")) in AGENT_POST and pending_page_of(["dns-filter", *w.split("/")]) == "dns-filter"
          for w in HELD_WEB), sorted(HELD_WEB))


class H:
    def __init__(self):
        self.out = None

    def redirect(self, location, headers=None):
        self.out = (303, location)

    def back(self, location, msg="", err=""):
        """A form's outcome (the console keeps it for the next page, 1.8.6.3), written as msg=/err= for these checks,
        before the place on the page (#...)."""
        path, _, frag = location.partition("#")
        q = urllib.parse.urlencode({"err": err} if err else {"msg": msg} if msg else {})
        self.redirect(path + (("&" if "?" in path else "?") + q if q else "") + (f"#{frag}" if frag else ""))

    def deny(self, status, text):
        self.out = (status, text)

    def send(self, status, body):
        self.out = (status, body)


class FakeActions:
    ValidationError = ValidationError

    def __init__(self, refuse=None, pending=1, apply_refuse=None):
        self.refuse, self.pending, self.apply_refuse, self.calls = refuse, pending, apply_refuse, []

    def hold_change(self, route, body):
        self.calls.append(("hold", route, body))
        if self.refuse:
            raise ValidationError(self.refuse)
        return {"id": "c1" if self.pending else None, "page": "dns-filter", "what": f"the change {route}",
                "pending": self.pending}

    def pending_action(self, page, op, change_id=None):
        self.calls.append((op, page))
        if self.apply_refuse:
            raise ValidationError(self.apply_refuse)
        return {"id": "job-1"}

    def dns_filter_change(self, what, body):
        self.calls.append(("now", what, body))
        if self.refuse:
            raise ValidationError(self.refuse)
        return {"fetching": True}


def use(fake):
    wpost.actions = wheld.actions = fake
    return fake


SESS = {"user": "alice", "csrf": "t"}
h, fake = H(), use(FakeActions())
wpost.dns_filter_post(h, SESS, ["rules"], {"kind": "block", "name": "x.example", "back": "querylog"})
# covers: web:post.dns-filter.rules +
check("web: Block from the query log is held for Apply, back to the query log where it was, saying it waits",
      h.out[0] == 303 and h.out[1].startswith("/dns-filter?view=querylog&msg=Waiting+for+Apply")
      and h.out[1].endswith("#querylog") and fake.calls == [("hold", "dns-filter/rules",
                                                              {"kind": "block", "name": "x.example"})], (h.out, fake.calls))
wpost.dns_filter_post(h, SESS, ["rules"], {"kind": "allow", "name": "y.example", "group": "Kids", "back": "groups"})
check("web: a group's rule goes back to that group's card", h.out[1].endswith("#group-kids"), h.out)
wpost.dns_filter_post(h, SESS, ["lists"], {"name": "Two", "url": "https://x/2", "back": "<script>"})
# covers: web:post.dns-filter.lists +
check("web: a list added by URL is held; a back section that is not one is ignored (the change's own section)",
      h.out[1].startswith("/dns-filter?view=lists&msg=") and h.out[1].endswith("#lists")
      and fake.calls[-1][1] == "dns-filter/lists", h.out)
wpost.dns_filter_post(h, SESS, ["lists", "delete"], {"url": "https://x/2", "on-abc": "on", "shown": "abc"})
# covers: web:post.dns-filter.lists.delete +
check("web: Remove (posted from inside the lists form) holds the removal with its URL only",
      fake.calls[-1] == ("hold", "dns-filter/lists/delete", {"url": "https://x/2"}) and "#lists" in h.out[1],
      fake.calls[-1:])
wpost.dns_filter_post(h, SESS, ["safe-search"], {"group": "kids", "youtube": "strict", "back": "groups"})
# covers: web:post.dns-filter.safe-search +
check("web: safe search with the box unchecked holds no 'on' (off) for its group, back to its card on Groups",
      fake.calls[-1] == ("hold", "dns-filter/safe-search", {"group": "kids", "youtube": "strict"})
      and h.out[1].startswith("/dns-filter?view=groups&msg=") and h.out[1].endswith("#group-kids"),
      (fake.calls[-1:], h.out))
wpost.dns_filter_post(h, SESS, ["groups"], {"name": "kids", "clients": "192.168.1.64/27"})
# covers: web:post.dns-filter.groups +
check("web: a group's change goes back to its card on Groups",
      h.out[1].startswith("/dns-filter?view=groups&msg=") and h.out[1].endswith("#group-kids"), h.out)
wpost.dns_filter_post(h, SESS, ["groups", "delete"], {"name": "kids"})
# covers: web:post.dns-filter.groups.delete +
check("web: a group's removal goes back to Groups (its card is gone)", h.out[1].endswith("#add-group"), h.out)
wpost.dns_filter_post(h, SESS, ["upstreams"], {"upstreams": "9.9.9.9 dns.quad9.net"})
# covers: web:post.dns-filter.upstreams +
check("web: the upstreams go back to their card on Settings", h.out[1].startswith("/dns-filter?view=settings&msg=")
      and h.out[1].endswith("#upstreams"), h.out)
wpost.dns_filter_post(h, SESS, ["rules", "delete"], {"kind": "block", "name": "x.example"})
# covers: web:post.dns-filter.rules.delete +
check("web: a rule's removal is held, back to Rules", fake.calls[-1][1] == "dns-filter/rules/delete"
      and h.out[1].endswith("#rules"), h.out)
n = len(fake.calls)
wpost.dns_filter_post(h, SESS, ["fetch"], {})
# covers: web:post.dns-filter.fetch +
check("web: Fetch every list now is done at once, never held", fake.calls[n:] == [("now", "fetch", {})]
      and "Fetching+every+list" in h.out[1], (fake.calls[n:], h.out))
h, fake = H(), use(FakeActions(refuse="not a DNS name"))
wpost.dns_filter_post(h, SESS, ["rules"], {"kind": "block", "name": "bad!"})
# covers: web:post.dns-filter.rules -
check("web: a change fabric-agent refuses goes back with the reason (err), nothing held",
      "err=not+a+DNS+name" in h.out[1], h.out)
for what, form in ((["lists"], {"url": "ftp://x"}), (["lists", "delete"], {"url": "https://nope"}),
                   (["safe-search"], {"group": "nosuch"}), (["groups"], {"name": "Bad Name"}),
                   (["groups", "delete"], {"name": "nosuch"}), (["upstreams"], {"upstreams": ""}),
                   (["rules", "delete"], {"kind": "block", "name": "never.example"})):
    wpost.dns_filter_post(h, SESS, what, form)
    # covers: web:post.dns-filter.lists web:post.dns-filter.lists.delete web:post.dns-filter.safe-search -
    # covers: web:post.dns-filter.groups web:post.dns-filter.groups.delete web:post.dns-filter.upstreams -
    # covers: web:post.dns-filter.rules.delete -
    check(f"web: {'/'.join(what)} refused: back to its section with why", h.out[0] == 303
          and "err=not+a+DNS+name" in h.out[1] and f"view={wpost.BACK['/'.join(what)]}" in h.out[1], h.out)
h, fake = H(), use(FakeActions(refuse="the lists job could not start"))
wpost.dns_filter_post(h, SESS, ["fetch"], {})
# covers: web:post.dns-filter.fetch -
check("web: a fetch that cannot start says why", "err=the+lists+job+could+not+start" in h.out[1], h.out)
h = H()
wpost.dns_filter_post(h, SESS, ["lists", "set"], {})
check("web: the old one-tick post is gone (a 404): every tick goes through Apply changes", h.out[0] == 404, h.out)
wpost.dns_filter_post(h, SESS, ["lists", "rename"], {})
check("web: an unknown change is a 404", h.out[0] == 404, h.out)

# the lists form's Apply changes: every box at once, then the tab's Apply
h, fake = H(), use(FakeActions(pending=3))
wpost.dns_filter_post(h, SESS, ["lists", "apply"], {"on-aaa": "on", "on-ccc": "on", "on-zzz": "on",
                                                     "shown": "aaa bbb ccc", "version": "v1"})
# covers: web:post.dns-filter.lists.apply +
check("web: Apply changes sends every box of the lists shown at once (one hold), then applies the tab's changes, "
      "back to the lists saying how many",
      fake.calls == [("hold", "dns-filter/lists/ticks", {"on": ["aaa", "ccc"], "shown": ["aaa", "bbb", "ccc"],
                                                         "version": "v1"}), ("apply", "dns-filter")]
      and h.out[1].startswith("/dns-filter?view=lists&msg=Applying+3+changes") and h.out[1].endswith("#lists"),
      (fake.calls, h.out))
h, fake = H(), use(FakeActions(pending=0))
wpost.dns_filter_post(h, SESS, ["lists", "apply"], {"shown": "aaa", "version": "v1"})
check("web: Apply changes with no box changed and nothing waiting applies nothing, saying so",
      fake.calls == [("hold", "dns-filter/lists/ticks", {"on": [], "shown": ["aaa"], "version": "v1"})]
      and "Nothing+to+apply" in h.out[1], (fake.calls, h.out))
h, fake = H(), use(FakeActions(apply_refuse="your apply of this page is still running"))
wpost.dns_filter_post(h, SESS, ["lists", "apply"], {"shown": "aaa", "on-aaa": "on", "version": "v1"})
check("web: an Apply refused (one still running) says why and that the ticks wait",
      "err=your+apply+of+this+page+is+still+running" in h.out[1] and "wait+for+Apply" in h.out[1], h.out)

from fabriclib.dns_filter.common.safe_search import safe_search_summary  # noqa: E402
from webui.devpreview.sample_data import SAMPLE_DNS_FILTER  # noqa: E402
OV = {**copy.deepcopy(SAMPLE_DNS_FILTER), "safe_search_sites": safe_search_summary(),
      "stats": {"off": "Postgres is not installed"}, "lists_version": lists_version(SAMPLE_DNS_FILTER["lists"])}
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
check("page: the lists are one form: a real checkbox per list (the ticked ones checked), by category, with its "
      "memory and the limit, the page's version and every list shown, and one Apply changes",
      lists.count('action="/dns-filter/lists/apply"') == 1 and lists.count('type="checkbox" class="tickbox"')
      == len(OV["lists"]) and lists.count(" checked>") == sum(bool(r["enabled"]) for r in OV["lists"])
      and f'name="version" value="{OV["lists_version"]}"' in lists
      and f'name="shown" value="{" ".join(r["id"] for r in OV["lists"])}"' in lists
      and lists.count("<button>Apply changes</button>") == 1 and "Security" in lists and "~24.5 MiB" in lists
      and "of a limit of 1024 MiB" in lists and "/dns-filter/lists/set" not in lists, lists[:400])
check("page: no script on the page (the strict CSP stands)", "<script" not in lists)
check("page: only a list added by URL has Remove, a button of the lists form posting to its own action",
      lists.count('formaction="/dns-filter/lists/delete"') == 1 and ' action="/dns-filter/lists/delete"' not in lists)
check("page: with nothing waiting it says the ticks wait for Apply changes",
      "Your ticks wait until you press Apply changes." in lists)
waiting = views.dns_filter({**ctx("dns:filter"), "pending": {"/dns-filter": {"id": "dns-filter", "pending": 2,
                                                                             "running": False}}},
                           "lists", OV, None, SEARCH)
check("page: with other changes waiting it says how many, with Review, and that Apply changes makes them too",
      "2 other changes of this tab wait too" in waiting and 'href="/changes/dns-filter"' in waiting
      and 'http-equiv="refresh"' not in waiting, waiting[waiting.find("applyline"):][:400])
running = views.dns_filter({**ctx("dns:filter"), "pending": {"/dns-filter": {"id": "dns-filter", "pending": 0,
                                                                             "running": True}}},
                           "rules", OV, None, SEARCH)
check("page: while the tab's Apply runs the page refreshes itself (a meta refresh, no script) on its section",
      '<meta http-equiv="refresh" content="2;url=/dns-filter?view=rules">' in running, running[:600])
check("page: each section's cards carry the ids a post returns to",
      all(f'id="{i}"' in page for page, ids in (
          (lists, ["lists"]), (operator, ["rules"]), (groups, ["group-kids", "group-teen-laptop", "add-group"]),
          (views.dns_filter(ctx("dns:filter"), "settings", OV, None, SEARCH), ["safe-search", "upstreams"]),
          (admin, ["querylog"])) for i in ids))
seen = views.dns_filter(ctx("dns:querylog"), "lists", OV, LOG, SEARCH)
check("page: without dns:filter the ticks show but post nothing", "/dns-filter/lists/apply" not in seen
      and 'class="tick on"' in seen and "tickbox" not in seen)
check("page: everyone's safe search is in Settings",
      'action="/dns-filter/safe-search"' in views.dns_filter(ctx("dns:filter"), "settings", OV, None, SEARCH))
viewer = views.dns_filter(ctx("dns:querylog"), "groups", None, LOG, SEARCH)
check("page: without dns:filter no group form shows", "/dns-filter/groups" not in viewer
      and "/dns-filter/safe-search" not in viewer)

# ---- fabric's own queries in the query log (2.1.12.12, 1.12.3.16): the box, the note, a bad value
OWN_LOG = {**LOG, "own": False, "own_networks": ["10.255.0.0/24", "192.168.1.10/32", "127.0.0.0/8", "::1/128"]}
hidden = views.dns_filter(ctx("dns:filter", "dns:querylog"), "querylog", OV, OWN_LOG, SEARCH)
shown = views.dns_filter(ctx("dns:filter", "dns:querylog"), "querylog", OV, {**OWN_LOG, "own": True},
                         {**SEARCH, "own": "on"})
check("page: the query log's search has the box Show fabric's own queries, unticked by default, and says what it hid",
      '<input type="checkbox" name="own">' in hidden and "Show fabric's own queries" in hidden
      and "fabric's own queries are hidden" in hidden and "10.255.0.0/24, 192.168.1.10/32" in hidden, hidden[-900:])
check("page: with the box ticked it stays ticked (kept by the form) and the note is gone",
      '<input type="checkbox" name="own" checked>' in shown and "own queries are hidden" not in shown)
STATS = {"hours": [], "week": {"queries": 120, "blocked": 7, "own": 45}, "zones": [], "top_blocked": []}
over = views.dns_filter(ctx("dns:filter"), "overview", {**OV, "stats": STATS}, None, SEARCH)
check("page: the overview states how many of the 7 days' queries were fabric's own",
      "45 of them fabric's own" in over, over[over.find("Queries, last 7 days"):][:300])


class PageH:
    def send(self, status, body):
        self.out = (status, body)


class PageActions:
    ValidationError, PermissionDenied = ValidationError, PermissionError

    def __init__(self):
        self.calls = []

    def dns_filter_overview(self):
        return OV

    def query_log(self, *args):
        self.calls.append(args)
        return {**OWN_LOG, "own": args[4]}


import webui.routes.dns_filter_page as wpage  # noqa: E402
wpage.actions, ph = PageActions(), PageH()
wpage.dns_filter_page(ph, ctx("dns:filter", "dns:querylog"), {"view": "querylog", "own": "on"})
# covers: web:get.dns-filter +
check("web: the box ticked asks fabric-agent for fabric's own queries too (own True)",
      ph.out[0] == 200 and wpage.actions.calls[-1][4] is True, wpage.actions.calls)
wpage.dns_filter_page(ph, ctx("dns:filter", "dns:querylog"), {"view": "querylog"})
check("web: unticked, fabric's own stay hidden (own False)", wpage.actions.calls[-1][4] is False)
n = len(wpage.actions.calls)
wpage.dns_filter_page(ph, ctx("dns:filter", "dns:querylog"), {"view": "querylog", "own": "yes"})
# covers: web:get.dns-filter -
check("web: a value for the box other than on is refused in place of the results, saying why; nothing asked",
      ph.out[0] == 200 and "Show fabric&#39;s own queries is on or off" in ph.out[1] and len(wpage.actions.calls) == n,
      ph.out[1][-600:] if isinstance(ph.out[1], str) else ph.out)

# a refused lists Apply: the lists page again with why, the boxes as sent (or as the lists are now, when stale)
wpost.page_context = lambda sess: ctx("dns:filter")
ROWS = OV["lists"]
off = next(r for r in ROWS if not r["enabled"])           # a list not ticked, ticked in the refused form
h, fake = H(), use(FakeActions(refuse="the ticked lists do not fit: Big (~500 MiB) would take the set to about ..."))
form = {"shown": " ".join(r["id"] for r in ROWS), "version": OV["lists_version"], f"on-{off['id']}": "on",
        **{f"on-{r['id']}": "on" for r in ROWS if r["enabled"]}}
wpost.dns_filter_post(h, SESS, ["lists", "apply"], form)
# covers: web:post.dns-filter.lists.apply -
check("web: the memory refusal is the lists page again (no redirect) saying why, the boxes kept as sent, nothing "
      "applied",
      h.out[0] == 200 and "do not fit: Big (~500 MiB)" in h.out[1]
      and f'name="on-{off["id"]}" aria-label="Use {off["name"]}" checked>'.replace("'", "&#39;") in h.out[1]
      and [c[0] for c in fake.calls] == ["hold"], (fake.calls, h.out[1][h.out[1].find(off["id"]) - 80:][:300]
                                                   if h.out[0] == 200 else h.out))
h, fake = H(), use(FakeActions(refuse="the lists changed since this page was shown (another person, ...)"))
wpost.dns_filter_post(h, SESS, ["lists", "apply"], {**form, "version": "an older version"})
check("web: a stale page's Apply is refused saying why, the lists shown as they are now (not the boxes sent)",
      h.out[0] == 200 and "changed since this page was shown" in h.out[1]
      and f'name="on-{off["id"]}" aria-label="Use {off["name"]}">'.replace("'", "&#39;") in h.out[1], h.out[0])

# ---- the YouTube level applies only while safe search is on (owner 2026-10-17, 2.1.12.13)
off_ = views.dns_filter(ctx("dns:filter"), "settings", {**OV, "safe_search": {"on": False, "youtube": "moderate"}},
                        None, SEARCH)
on_ = views.dns_filter(ctx("dns:filter"), "settings", {**OV, "safe_search": {"on": True, "youtube": "moderate"}},
                       None, SEARCH)
check("page: safe search off: the YouTube select is disabled, says it is used only while safe search is on, and a "
      "hidden copy keeps the saved level when the form is saved",
      '<select name="youtube" disabled>' in off_ and "Used only while safe search is on." in off_
      and '<input type="hidden" name="youtube" value="moderate">' in off_, off_[off_.find("YouTube<"):][:500])
check("page: safe search on: the YouTube select is enabled and no hidden copy is sent",
      '<select name="youtube">' in on_ and 'type="hidden" name="youtube"' not in on_
      and "Used only while safe search is on." in on_)
ro = views.dns_filter(ctx("dns:querylog"), "settings", {**OV, "safe_search": {"on": True, "youtube": "strict"}},
                      None, SEARCH)
check("page: without dns:filter the select stays disabled, even with safe search on",
      '<select name="youtube" disabled>' in ro and 'type="hidden" name="youtube"' not in ro)

print("\nall passed (0 failures)" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
