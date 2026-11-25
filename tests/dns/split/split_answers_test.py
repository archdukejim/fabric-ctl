#!/usr/bin/env python3
"""Split DNS by zone, rendered (decision 2.1.4.18, manual 1.4.1.13): the networks with answers of their own and their
RPZ's local data (a split's differences from the All networks tab, with PTRs; "no such name" for a zone mapped to
other networks), the rest's ("no such name" for every mapped zone), fabric's own names untouched, a split's records in
no reverse zone (split_answers, reverse_zones); BIND's views (with a split only: the default view first, matching every
network but the split ones; with a zone mapped: the default view for signed requests, this host and fabric's
containers alone, then the networks' views, then everyone's with the rest's RPZ) and nothing changed for a site
without either; the resolver's views (a group's clients in such a network first, then the groups and everyone with
the rest's RPZ). Pure render; no container (both servers answering real clients is the sandbox's and the 0.10.2
testing's, 3.1.1).

    python3 tests/dns/split/split_answers_test.py
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dns.reverse_zones import reverse_zones  # noqa: E402
from fabriclib.dns.split.split_answers import split_answers  # noqa: E402
from fabriclib.dns_filter.resolver_views import resolver_views  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:900]}"))


LAN, IOT, IOT2 = "10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24"
PLAN = {"subnets": [{"name": "iot", "cidr": IOT}, {"name": "iot-2", "cidr": IOT2}, {"name": "guest",
                                                                                     "cidr": "10.1.30.0/24"}]}
BASE = {"A": [{"name": "nas", "ip": "192.168.1.10"}, {"name": "web", "ip": "192.168.1.11"},
              {"name": "old", "ip": "192.168.1.9"}, {"name": "core", "ip": "10.1.10.5"}],
        "CNAME": [{"name": "ca", "canonical": "core"}],
        "MX": [{"name": "@", "priority": 10, "exchange": "mail"}]}
SPLIT = {"subnets": [IOT, IOT2],
         "A": [{"name": "nas", "ip": "10.1.20.10"}, {"name": "web", "ip": "192.168.1.11"}],
         "CNAME": [{"name": "files", "canonical": "nas"}],
         "MX": [{"name": "@", "priority": 10, "exchange": "mail"}]}
V = {"domain": "home.arpa", "hostname": "core", "host_ip": "10.1.10.5", "lan_cidr": LAN,
     "fabric_subnet": "10.255.0.0/24",
     "dns": {"dynamic_zone_var": {**BASE, "splits": [SPLIT]},
             "iot.lan": {"networks": [IOT], "A": [{"name": "hello", "ip": "10.1.20.5"}]},
             "plain.lan": {"A": [{"name": "x", "ip": "10.1.10.8"}]}},
     "tsig_keys": [{"name": "home.arpa-acme", "algorithm": "hmac-sha256", "domain": "home.arpa", "records": ["nas"],
                    "record_types": ["TXT"]}], "tsig_secrets": {"home.arpa-acme": "x"},
     "bind_acls": {"trusted": ["any"]}, "install_kea": True, "dhcp": {"ddns": True}, "kea_ddns_secret": "y",
     "reverse_zone_names": ["10.1.10.in-addr.arpa"], "bind_dns_port": 53}

print("--- split_answers and reverse_zones")
out = split_answers(V, PLAN)
views, rest = out["views"], out["rest"]
by = {s["ref"]: s for s in views}
check("the networks with answers of their own: the split's two and the mapped zone's one, each once, in the plan's "
      "order; the host's LAN (in neither) and the guest network have none", [s["ref"] for s in views] == [IOT, IOT2],
      views)
SPLIT_LINES = ["nas.home.arpa A 10.1.20.10", "10.1.168.192.in-addr.arpa CNAME .", "old.home.arpa CNAME .",
               "9.1.168.192.in-addr.arpa CNAME .", "10.20.1.10.in-addr.arpa PTR nas.home.arpa.",
               "files.home.arpa CNAME nas.home.arpa."]
s = by.get(IOT, {})
check("10.1.20.0/24: its view, its RPZ, the one network", s.get("view") == "subnet-10-1-20-0-24"
      and s.get("rpz") == "split-10-1-20-0-24.rpz" and s.get("cidrs") == [IOT], s)
check("its local data: the split's differences only (nas changed, old gone, files new; web and the apex's MX the "
      "same so left to the zone), each PTR beside its record, an All networks PTR the split drops gone",
      s.get("lines") == SPLIT_LINES, s.get("lines"))
check("fabric's own names (core, ca) are never in a split's answers: they answer in every tab",
      not any(o.startswith(("core.", "ca.", "5.10.1.10.")) for o in s.get("lines", [])), s.get("lines"))
check("10.1.21.0/24: the same split, and the zone mapped to 10.1.20.0/24 alone hidden, its apex, everything under it "
      "and its PTRs", by.get(IOT2, {}).get("lines") == SPLIT_LINES + ["iot.lan CNAME .", "*.iot.lan CNAME .",
                                                                      "5.20.1.10.in-addr.arpa CNAME ."], by.get(IOT2))
check("the rest (in no such network): every mapped zone hidden, the split's answers not", rest and rest["rpz"]
      == "split-rest.rpz" and rest["view"] == "everyone" and rest["cidrs"] == ["any"] and rest["lines"]
      == ["iot.lan CNAME .", "*.iot.lan CNAME .", "5.20.1.10.in-addr.arpa CNAME ."], rest)
check("negative: a zone that answers every network with no split (plain.lan) is in no RPZ",
      not any("plain.lan" in line or "8.10.1.10" in line for x in views + [rest] for line in x["lines"]))
check("no plan read yet: only the host's LAN is offered, so no network of these has a view (they answer as the rest)",
      split_answers(V, {})["views"] == [])
WIDE = {**V, "dns": {"z": {"A": [{"name": "a", "ip": "10.1.20.3"}],
                           "splits": [{"subnets": ["10.1.0.0/16"], "A": [{"name": "a", "ip": "10.1.20.4"}]},
                                      {"subnets": [IOT], "A": [{"name": "a", "ip": "10.1.20.5"}]}]}}}
check("the most specific network first, so a client in both gets the smaller one's answers",
      [x["ref"] for x in split_answers(WIDE, {"subnets": [{"name": "wide", "cidr": "10.1.0.0/16"},
                                                          {"name": "iot", "cidr": IOT}]})["views"]]
      == [IOT, "10.1.0.0/16"])
check("negative: a site with no mapped or split zone: no view, no rest",
      split_answers({**V, "dns": {"plain.lan": V["dns"]["plain.lan"]}}, PLAN) == {"views": [], "rest": None})
rev = reverse_zones(V)["zones"]
ptrs = {(z, r["label"], r.get("target")) for z, recs in rev.items() for r in recs}
check("reverse zones: the All networks tab's PTRs as before", any(z == "1.168.192.in-addr.arpa" and lab == "10"
                                                                  for z, lab, _ in ptrs), rev)
check("negative: a split's own record has no PTR in any reverse zone (its name not given away elsewhere)",
      not any(z == "20.1.10.in-addr.arpa" and lab == "10" for z, lab, _ in ptrs), rev)

print("--- BIND (1.4.1.11, 1.4.1.13)")
TPL = jinja_env(os.path.join(REPO, "templates"))
conf = TPL.get_template("bind9/config/named.conf.j2").render(**V, split_views=out)
at = {n: conf.find(f'view "{n}"') for n in ("default", "subnet-10-1-20-0-24", "subnet-10-1-21-0-24", "everyone")}
check("views in order: the default view (in-view needs it first), the networks', then everyone's",
      0 < at["default"] < at["subnet-10-1-20-0-24"] < at["subnet-10-1-21-0-24"] < at["everyone"], at)
m = re.search(r'view "default" \{\n    match-clients \{ (.*?) \};', conf)
check("a zone mapped: the default view matches only signed requests, this host and fabric's containers",
      m and m.group(1) == 'key "kea-ddns"; key "home.arpa-acme"; 127.0.0.1; 10.1.10.5; 10.255.0.0/24;',
      m and m.group(1))
check("the default view holds every zone and the AD zone's DLZ", conf.count('include "/etc/bind/named.conf.zones";')
      == 1 and conf.index('include "/etc/bind-samba/dlz.conf"') < at["subnet-10-1-20-0-24"])
block = conf[at["subnet-10-1-20-0-24"]:at["subnet-10-1-21-0-24"]]
check("10.1.20.0/24's view: the network, its RPZ as a zone and as the policy on authoritative answers",
      "match-clients { 10.1.20.0/24; };" in block
      and 'zone "split-10-1-20-0-24.rpz" { type primary; file "/var/lib/bind/db.split-10-1-20-0-24.rpz";' in block
      and 'response-policy { zone "split-10-1-20-0-24.rpz"; } recursive-only no break-dnssec yes;' in block, block)
check("...every zone shared from the default view, none copied: the forward zones, Kea's, the reverse ones",
      all(f'zone "{z}" {{ in-view "default"; }};' in block
          for z in ("home.arpa", "iot.lan", "plain.lan", "dhcp.home.arpa", "10.1.10.in-addr.arpa"))
      and "type master" not in block and "dlz" not in block, block)
every = conf[at["everyone"]:]
check("everyone's view: any client left, the rest's RPZ, every zone shared", "match-clients { any; };" in every
      and 'response-policy { zone "split-rest.rpz"; } recursive-only no' in every
      and 'zone "iot.lan" { in-view "default"; };' in every and "dlz" not in every, every)
zones = TPL.get_template("bind9/config/named.conf.zones.j2").render(**V)
check("...the zones shared are exactly the zones the default view serves",
      sorted(re.findall(r'^zone "([^"]+)" \{\n', zones, re.M))
      == sorted(re.findall(r'zone "([^"]+)" \{ in-view', block)), (zones, block))
only = {**V, "dns": {"dynamic_zone_var": V["dns"]["dynamic_zone_var"]}}
conf2 = TPL.get_template("bind9/config/named.conf.j2").render(**only, split_views=split_answers(only, PLAN))
m = re.search(r'view "default" \{\n    match-clients \{ (.*?) \};', conf2)
check("a split and no zone mapped: the default view takes every network but the split ones, and no everyone view",
      m and m.group(1).endswith("10.255.0.0/24; !10.1.20.0/24; !10.1.21.0/24; any;") and 'view "everyone"'
      not in conf2, m and m.group(1))
same = TPL.get_template("bind9/config/named.conf.j2").render(**V, split_views={"views": [], "rest": None})
check("negative: no network with answers of its own: no view at all, the configuration as before",
      "view" not in same and same.rstrip().endswith('include "/etc/bind-samba/dlz.conf";'), same)
rpz = TPL.get_template("bind9/data/split.rpz.j2").render(**V, split=s)
check("10.1.20.0/24's RPZ file: a serial reload_zone reads, the NS, its local data and PTRs",
      re.search(r"^\s*\d+ ; Serial", rpz, re.M) and "@       IN      NS      localhost." in rpz
      and "files.home.arpa CNAME nas.home.arpa." in rpz and "old.home.arpa CNAME ." in rpz, rpz)

print("--- the resolver (1.12.2.15, 1.12.3.6)")
G = {**V, "dns_filter_groups": [{"name": "kids", "clients": ["10.1.20.64/26", "10.9.0.0/16"], "safe_search": True,
                                 "youtube": "strict"},
                                {"name": "adults", "clients": ["10.1.0.0/16"], "safe_search": False,
                                 "youtube": "strict"},
                                {"name": "guests", "clients": ["10.5.0.0/24"], "safe_search": False,
                                 "youtube": "strict"}],
     "dns_filter_safe_search": False}
rv = resolver_views(G, PLAN)
pairs = {p["name"]: p["match"] for p in rv["pairs"]}
check("a group with clients in a network with answers gets a view there: its clients inside it",
      pairs == {"kids-subnet-10-1-20-0-24": ["10.1.20.64/26"], "adults-subnet-10-1-20-0-24": ["!10.1.20.64/26", IOT],
                "adults-subnet-10-1-21-0-24": ["!10.1.20.64/26", IOT2]}, pairs)
check("negative: a group with no client in the network gets no such view", not any(n.startswith("guests-")
                                                                                   for n in pairs))
check("each network's own view: the network, its RPZ", rv["subnets"][0] == {
    "name": "subnet-10-1-20-0-24", "match": [IOT], "split": "split-10-1-20-0-24.rpz"}, rv["subnets"])
check("the groups' own views get the rest's RPZ (a zone is mapped)", all(g["split"] == "split-rest.rpz"
                                                                         for g in rv["groups"]), rv["groups"])
ctx = {**G, "groups": rv["groups"], "pairs": rv["pairs"], "subnets": rv["subnets"], "rest": rv["rest"],
       "zones": ["home.arpa"], "safe_zone": None, "clients": ["10.1.0.0/16"], "deny": [], "client_tls": False,
       "adguard_tls": True, "ip_bind9": "10.255.0.53", "ip_adguard": "10.255.0.54", "resolver_rndc_secret": "z"}
res = TPL.get_template("resolver/config/named.conf.j2").render(**ctx)
order = re.findall(r'^view "([^"]+)"', res, re.M)
check("the views in order: the pairs, the groups, the networks, everyone (the most specific wins)",
      order == list(pairs) + ["kids", "adults", "guests", "subnet-10-1-20-0-24", "subnet-10-1-21-0-24", "everyone"],
      order)
pair = res[res.index('view "kids-subnet-10-1-20-0-24"'):res.index('view "adults-subnet-10-1-20-0-24"')]
check("a pair's view: the group's filtering with the network's answers first, not the rest's",
      'tls "group-kids"' in pair and 'zone "group-kids.rpz"' in pair
      and pair.index('zone "split-10-1-20-0-24.rpz";') < pair.index('zone "fabric.rpz";')
      and "split-rest" not in pair, pair)
grp = res[res.index('view "kids"'):res.index('view "adults"')]
check("a group's own view (its clients elsewhere): the rest's answers first", 'zone "split-rest.rpz" { type primary;'
      in grp and grp.index('zone "split-rest.rpz";') < grp.index('zone "fabric.rpz";'), grp)
every_r = res[res.index('view "everyone"'):]
check("everyone's view: the rest's answers first", "match-clients { any; };" in every_r
      and every_r.index('zone "split-rest.rpz";') < every_r.index('zone "fabric.rpz";'), every_r)
plain_views = resolver_views({**G, "dns": {}}, PLAN)
check("negative: nothing mapped or split: no pair, no network view, no rest, the groups' views as before",
      not plain_views["pairs"] and not plain_views["subnets"] and plain_views["rest"] is None
      and all(g["split"] is None for g in plain_views["groups"]))
res0 = TPL.get_template("resolver/config/named.conf.j2").render(**{**ctx, **{k: plain_views[k] for k in (
    "groups", "pairs", "subnets", "rest")}})
check("...and no split- zone in the resolver's configuration", "split-" not in res0, res0[:600])

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
