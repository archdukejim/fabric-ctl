#!/usr/bin/env python3
"""Split DNS, rendered (decision 2.1.4.16, manual 1.4.1.11): which VLANs have answers of their own and their RPZ's
local data (split_answers), the zone file without them (default_records), BIND's views (the default view first:
signed requests, this host and fabric's containers, every network but the split VLANs'; each VLAN's view sharing
every zone with in-view and answering from its RPZ) and nothing changed for a site without them, and the resolver's
views (a group's clients in such a VLAN first, then the groups, the VLANs, everyone). Pure render; no container
(BIND taking the views is the 0.10.0 testing's, 2.1.1.102).

    python3 tests/dns/split/split_answers_test.py
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dns.split.default_records import default_records  # noqa: E402
from fabriclib.dns.split.split_answers import split_answers  # noqa: E402
from fabriclib.dns_filter.resolver_views import resolver_views  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))


PLAN = {"vlans": [{"id": 10, "location": ""}, {"id": 20, "location": ""}, {"id": 30, "location": ""}],
        "subnets": [{"cidr": "10.1.10.0/24", "vlan": 10, "location": ""}, {"cidr": "10.1.20.0/24", "vlan": 20,
                                                                           "location": ""},
                    {"cidr": "10.1.21.0/24", "vlan": 20, "location": ""}]}
V = {"domain": "home.arpa", "host_ip": "10.1.10.5", "lan_cidr": "10.1.10.0/24", "fabric_subnet": "10.255.0.0/24",
     "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"},
                                        {"name": "nas", "ip": "10.1.20.10", "vlan": "20"},
                                        {"name": "@", "ip": "10.1.20.1", "vlan": "20"},
                                        {"name": "lost", "ip": "10.1.30.9", "vlan": "30"},
                                        {"name": "gone", "ip": "10.1.40.9", "vlan": "40"}],
                                  "CNAME": [{"name": "files", "canonical": "nas", "vlan": "20"},
                                            {"name": "web", "canonical": "proxy.example.com."}],
                                  "MX": [{"name": "@", "priority": 10, "exchange": "mail", "vlan": "20"}]},
             "iot.lan": {"TXT": [{"name": "hello", "text": "v=one", "vlan": "20"}]}},
     "tsig_keys": [{"name": "home.arpa-acme", "algorithm": "hmac-sha256", "domain": "home.arpa", "records": ["nas"],
                    "record_types": ["TXT"]}], "tsig_secrets": {"home.arpa-acme": "x"},
     "bind_acls": {"trusted": ["any"]}, "install_kea": True, "dhcp": {"ddns": True}, "kea_ddns_secret": "y",
     "reverse_zone_names": ["10.1.10.in-addr.arpa"], "bind_dns_port": 53}

print("--- split_answers and default_records")
split = split_answers(V, PLAN)
check("only VLAN 20 has answers of its own: 30 has no subnet, 40 is not in the plan",
      [s["ref"] for s in split] == ["20"], split)
s = split[0] if split else {}
check("VLAN 20: its view, its RPZ, its subnets, its names", s.get("view") == "vlan-20" and s.get("rpz") ==
      "split-20.rpz" and s.get("cidrs") == ["10.1.20.0/24", "10.1.21.0/24"]
      and s.get("names") == ["nas.home.arpa", "home.arpa", "files.home.arpa", "hello.iot.lan"], s)
check("its local data: the owner relative to the RPZ, every target in full (relative to its zone, or as written)",
      s.get("lines") == ["nas.home.arpa A 10.1.20.10", "home.arpa A 10.1.20.1",
                         "files.home.arpa CNAME nas.home.arpa.", "home.arpa MX 10 mail.home.arpa.",
                         'hello.iot.lan TXT "v=one"'], s.get("lines"))
check("no plan read yet: no VLAN has answers (nothing to match them by)", split_answers(V, {}) == [])
plain = default_records(V["dns"]["dynamic_zone_var"])
check("the zone as everyone gets it: a VLAN's records left out, the rest kept",
      plain["A"] == [{"name": "nas", "ip": "192.168.1.10"}] and plain["CNAME"] == [{"name": "web",
                                                                                   "canonical": "proxy.example.com."}]
      and plain["MX"] == [], plain)

print("--- BIND (1.4.1.11)")
TPL = jinja_env(os.path.join(REPO, "templates"))
conf = TPL.get_template("bind9/config/named.conf.j2").render(**V, split_views=split)
default_at, vlan_at = conf.find('view "default"'), conf.find('view "vlan-20"')
check("views: the default view first (in-view needs it defined before), then VLAN 20's",
      0 < default_at < vlan_at, conf)
m = re.search(r'view "default" \{\n    match-clients \{ (.*?) \};', conf)
check("the default view matches signed requests (Kea's, ACME's keys) first, this host and fabric's containers, then "
      "every network but VLAN 20's", m and m.group(1) == 'key "kea-ddns"; key "home.arpa-acme"; 127.0.0.1; '
      '10.1.10.5; 10.255.0.0/24; !10.1.20.0/24; !10.1.21.0/24; any;', m and m.group(1))
check("the default view holds every zone and the AD zone's DLZ", conf.count('include "/etc/bind/named.conf.zones";')
      == 1 and conf.index('include "/etc/bind-samba/dlz.conf"') < vlan_at)
block = conf[vlan_at:]
check("VLAN 20's view: its subnets, its RPZ as a zone and as the policy on authoritative answers",
      "match-clients { 10.1.20.0/24; 10.1.21.0/24; };" in block
      and 'zone "split-20.rpz" { type primary; file "/var/lib/bind/db.split-20.rpz";' in block
      and 'response-policy { zone "split-20.rpz"; } recursive-only no break-dnssec yes;' in block, block)
check("...every zone shared from the default view, none copied: the forward zones, Kea's, the reverse ones",
      all(f'zone "{z}" {{ in-view "default"; }};' in block
          for z in ("home.arpa", "iot.lan", "dhcp.home.arpa", "10.1.10.in-addr.arpa"))
      and "type master" not in block and "dlz" not in block, block)
zones = TPL.get_template("bind9/config/named.conf.zones.j2").render(**V)
check("...the zones shared are exactly the zones the default view serves",
      sorted(re.findall(r'^zone "([^"]+)" \{\n', zones, re.M))
      == sorted(re.findall(r'zone "([^"]+)" \{ in-view', block)), (zones, block))
same = TPL.get_template("bind9/config/named.conf.j2").render(**V, split_views=[])
check("negative: no VLAN with answers of its own: no view at all, the configuration as before",
      "view" not in same and same.rstrip().endswith('include "/etc/bind-samba/dlz.conf";'), same)
rpz = TPL.get_template("bind9/data/split.rpz.j2").render(**V, split=s)
check("VLAN 20's RPZ file: a serial reload_zone reads, the NS, its local data",
      re.search(r"^\s*\d+ ; Serial", rpz, re.M) and "@       IN      NS      localhost." in rpz
      and "files.home.arpa CNAME nas.home.arpa." in rpz, rpz)

print("--- the resolver (1.12.2.15, 1.12.3.6)")
G = {**V, "dns_filter_groups": [{"name": "kids", "clients": ["10.1.20.64/26", "10.9.0.0/16"], "safe_search": True,
                                 "youtube": "strict"},
                                {"name": "adults", "clients": ["10.1.0.0/16"], "safe_search": False,
                                 "youtube": "strict"},
                                {"name": "guests", "clients": ["10.5.0.0/24"], "safe_search": False,
                                 "youtube": "strict"}],
     "dns_filter_safe_search": False}
views = resolver_views(G, PLAN)
pairs = {p["name"]: p["match"] for p in views["pairs"]}
check("a group with clients in VLAN 20 gets a view there: its clients inside it (the smaller of each pair)",
      pairs == {"kids-vlan-20": ["10.1.20.64/26"],
                "adults-vlan-20": ["!10.1.20.64/26", "10.1.20.0/24", "10.1.21.0/24"]}, pairs)
check("negative: a group with no client in the VLAN gets no such view", "guests-vlan-20" not in pairs)
check("VLAN 20's own view: its subnets, its RPZ", views["vlans"] == [{"name": "vlan-20", "match": ["10.1.20.0/24",
                                                                                                   "10.1.21.0/24"],
                                                                      "split": "split-20.rpz"}], views["vlans"])
ctx = {**G, "groups": views["groups"], "pairs": views["pairs"], "vlans": views["vlans"], "zones": ["home.arpa"],
       "safe_zone": None, "clients": ["10.1.0.0/16"], "deny": [], "client_tls": False, "adguard_tls": True,
       "ip_bind9": "10.255.0.53", "ip_adguard": "10.255.0.54", "resolver_rndc_secret": "z"}
res = TPL.get_template("resolver/config/named.conf.j2").render(**ctx)
order = [m for m in re.findall(r'^view "([^"]+)"', res, re.M)]
check("the views in order: the pairs, the groups, the VLAN, everyone (the most specific wins)",
      order == ["kids-vlan-20", "adults-vlan-20", "kids", "adults", "guests", "vlan-20", "everyone"], order)
pair = res[res.index('view "kids-vlan-20"'):res.index('view "adults-vlan-20"')]
check("a pair's view: the group's filtering (its DoT name, rules, safe search) with the VLAN's answers first",
      'tls "group-kids"' in pair and 'zone "group-kids.rpz"' in pair and 'zone "split-20.rpz" { type primary;' in pair
      and pair.index('zone "split-20.rpz";') < pair.index('zone "fabric.rpz";'), pair)
vlan = res[res.index('view "vlan-20"'):res.index('view "everyone"')]
check("the VLAN's view: everyone's filtering with its answers first", 'match-clients { 10.1.20.0/24; 10.1.21.0/24; };'
      in vlan and vlan.index('zone "split-20.rpz";') < vlan.index('zone "fabric.rpz";')
      and "group-" not in vlan, vlan)
every = res[res.index('view "everyone"'):]
check("negative: everyone's view has no VLAN's answers", "split-" not in every and "match-clients { any; };" in every,
      every)
grp = res[res.index('view "kids"'):res.index('view "adults"')]
check("negative: a group's own view (its clients outside the VLAN) has no VLAN's answers", "split-" not in grp, grp)
plain_views = resolver_views({**G, "dns": {}}, PLAN)
check("negative: no VLAN with answers: no pair and no VLAN view", not plain_views["pairs"]
      and not plain_views["vlans"])

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
