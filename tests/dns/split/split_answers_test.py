#!/usr/bin/env python3
"""Split DNS by subnet, rendered (decision 2.1.4.17, manual 1.4.1.12): which subnets have answers of their own and
their RPZ's local data, a record's PTR there and in no reverse zone (split_answers, reverse_zones), the zone file
without them (default_records), BIND's views (the default view first: signed requests, this host and fabric's
containers, every network but the split subnets'; each subnet's view sharing every zone with in-view and answering
from its RPZ; the most specific subnet first) and nothing changed for a site without them, and the resolver's views (a
group's clients in such a subnet first, then the groups, the subnets, everyone). Pure render; no container (both
servers answering a client of each subnet is the 0.10.2 testing's, 3.1.1).

    python3 tests/dns/split/split_answers_test.py
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dns.reverse_zones import reverse_zones  # noqa: E402
from fabriclib.dns.split.default_records import default_records  # noqa: E402
from fabriclib.dns.split.split_answers import split_answers  # noqa: E402
from fabriclib.dns_filter.resolver_views import resolver_views  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))


LAN, IOT, IOT2 = "10.1.10.0/24", "10.1.20.0/24", "10.1.21.0/24"
PLAN = {"subnets": [{"name": "iot", "cidr": IOT}, {"name": "iot-2", "cidr": IOT2}, {"name": "guest",
                                                                                     "cidr": "10.1.30.0/24"}]}
V = {"domain": "home.arpa", "host_ip": "10.1.10.5", "lan_cidr": LAN, "fabric_subnet": "10.255.0.0/24",
     "dns": {"dynamic_zone_var": {"A": [{"name": "nas", "ip": "192.168.1.10"},
                                        {"name": "nas", "ip": "10.1.20.10", "subnets": [IOT, IOT2]},
                                        {"name": "@", "ip": "10.1.20.1", "subnets": [IOT]},
                                        {"name": "printer", "ip": "10.1.10.7", "subnets": [LAN]},
                                        {"name": "gone", "ip": "10.1.40.9", "subnets": ["10.1.40.0/24"]},
                                        {"name": "nobody", "ip": "10.1.20.99", "subnets": []}],
                                  "CNAME": [{"name": "files", "canonical": "nas", "subnets": [IOT]},
                                            {"name": "web", "canonical": "proxy.example.com."}],
                                  "MX": [{"name": "@", "priority": 10, "exchange": "mail", "subnets": [IOT]}]},
             "iot.lan": {"TXT": [{"name": "hello", "text": "v=one", "subnets": [IOT]}]}},
     "tsig_keys": [{"name": "home.arpa-acme", "algorithm": "hmac-sha256", "domain": "home.arpa", "records": ["nas"],
                    "record_types": ["TXT"]}], "tsig_secrets": {"home.arpa-acme": "x"},
     "bind_acls": {"trusted": ["any"]}, "install_kea": True, "dhcp": {"ddns": True}, "kea_ddns_secret": "y",
     "reverse_zone_names": ["10.1.10.in-addr.arpa"], "bind_dns_port": 53}

print("--- split_answers, default_records and reverse_zones")
split = split_answers(V, PLAN)
by = {s["ref"]: s for s in split}
check("the subnets with answers of their own: the host's LAN first, then the plan's in order; 10.1.40.0/24 is "
      "offered by nothing, 10.1.30.0/24 has no record", [s["ref"] for s in split] == [LAN, IOT, IOT2], split)
s = by.get(IOT, {})
check("10.1.20.0/24: its view, its RPZ, the one subnet, its names (PTRs are not names it answers alone)",
      s.get("view") == "subnet-10-1-20-0-24" and s.get("rpz") == "split-10-1-20-0-24.rpz" and s.get("cidrs") == [IOT]
      and s.get("names") == ["nas.home.arpa", "home.arpa", "files.home.arpa", "hello.iot.lan"], s)
check("its local data: the owner relative to the RPZ, every target in full; each A record's PTR beside it",
      s.get("lines") == ["nas.home.arpa A 10.1.20.10", "10.20.1.10.in-addr.arpa PTR nas.home.arpa.",
                         "home.arpa A 10.1.20.1", "1.20.1.10.in-addr.arpa PTR home.arpa.",
                         "files.home.arpa CNAME nas.home.arpa.", "home.arpa MX 10 mail.home.arpa.",
                         'hello.iot.lan TXT "v=one"'], s.get("lines"))
check("a record for two subnets is in both: 10.1.21.0/24 holds nas and its PTR alone",
      by.get(IOT2, {}).get("lines") == ["nas.home.arpa A 10.1.20.10", "10.20.1.10.in-addr.arpa PTR nas.home.arpa."],
      by.get(IOT2))
check("the host's LAN's own: printer and its PTR", by.get(LAN, {}).get("lines")
      == ["printer.home.arpa A 10.1.10.7", "7.10.1.10.in-addr.arpa PTR printer.home.arpa."], by.get(LAN))
check("negative: a record with no subnet answers no one (no view takes it)",
      not any("nobody" in line for x in split for line in x["lines"]))
check("no plan read yet: the host's LAN alone is offered", [x["ref"] for x in split_answers(V, {})] == [LAN])
WIDE = {**V, "dns": {"z": {"A": [{"name": "a", "ip": "10.1.20.3", "subnets": ["10.1.0.0/16"]},
                                 {"name": "b", "ip": "10.1.20.4", "subnets": [IOT]}]}}}
check("the most specific subnet first, so a client in both gets the smaller one's answers",
      [x["ref"] for x in split_answers(WIDE, {"subnets": [{"name": "wide", "cidr": "10.1.0.0/16"},
                                                          {"name": "iot", "cidr": IOT}]})] == [IOT, "10.1.0.0/16"])
plain = default_records(V["dns"]["dynamic_zone_var"])
check("the zone as every subnet gets it: records for some subnets left out, the rest kept",
      plain["A"] == [{"name": "nas", "ip": "192.168.1.10"}] and plain["CNAME"] == [{"name": "web",
                                                                                   "canonical": "proxy.example.com."}]
      and plain["MX"] == [], plain)
rev = reverse_zones(V)["zones"]
ptrs = {(z, r["label"]) for z, recs in rev.items() for r in recs}
check("reverse zones: an every-subnet record keeps its PTR there (2.1.4.17 point 1)", ("1.168.192.in-addr.arpa", "10")
      in ptrs, rev)
check("negative: a record for some subnets has no PTR in any reverse zone (its name not given away elsewhere)",
      ("10.1.10.in-addr.arpa", "7") not in ptrs and ("20.1.10.in-addr.arpa", "10") not in ptrs, rev)

print("--- BIND (1.4.1.11, 1.4.1.12)")
TPL = jinja_env(os.path.join(REPO, "templates"))
conf = TPL.get_template("bind9/config/named.conf.j2").render(**V, split_views=split)
default_at, iot_at = conf.find('view "default"'), conf.find('view "subnet-10-1-20-0-24"')
check("views: the default view first (in-view needs it defined before), then the subnets'",
      0 < default_at < conf.find('view "subnet-10-1-10-0-24"') < iot_at, conf)
m = re.search(r'view "default" \{\n    match-clients \{ (.*?) \};', conf)
check("the default view matches signed requests first, this host and fabric's containers, then every network but "
      "the split subnets' (so this host stays in it, though its LAN is split)",
      m and m.group(1) == 'key "kea-ddns"; key "home.arpa-acme"; 127.0.0.1; 10.1.10.5; 10.255.0.0/24; '
      '!10.1.10.0/24; !10.1.20.0/24; !10.1.21.0/24; any;', m and m.group(1))
check("the default view holds every zone and the AD zone's DLZ", conf.count('include "/etc/bind/named.conf.zones";')
      == 1 and conf.index('include "/etc/bind-samba/dlz.conf"') < iot_at)
block = conf[iot_at:conf.find('view "subnet-10-1-21-0-24"')]
check("10.1.20.0/24's view: the subnet, its RPZ as a zone and as the policy on authoritative answers",
      "match-clients { 10.1.20.0/24; };" in block
      and 'zone "split-10-1-20-0-24.rpz" { type primary; file "/var/lib/bind/db.split-10-1-20-0-24.rpz";' in block
      and 'response-policy { zone "split-10-1-20-0-24.rpz"; } recursive-only no break-dnssec yes;' in block, block)
check("...every zone shared from the default view, none copied: the forward zones, Kea's, the reverse ones",
      all(f'zone "{z}" {{ in-view "default"; }};' in block
          for z in ("home.arpa", "iot.lan", "dhcp.home.arpa", "10.1.10.in-addr.arpa"))
      and "type master" not in block and "dlz" not in block, block)
zones = TPL.get_template("bind9/config/named.conf.zones.j2").render(**V)
check("...the zones shared are exactly the zones the default view serves",
      sorted(re.findall(r'^zone "([^"]+)" \{\n', zones, re.M))
      == sorted(re.findall(r'zone "([^"]+)" \{ in-view', block)), (zones, block))
same = TPL.get_template("bind9/config/named.conf.j2").render(**V, split_views=[])
check("negative: no subnet with answers of its own: no view at all, the configuration as before",
      "view" not in same and same.rstrip().endswith('include "/etc/bind-samba/dlz.conf";'), same)
rpz = TPL.get_template("bind9/data/split.rpz.j2").render(**V, split=s)
check("10.1.20.0/24's RPZ file: a serial reload_zone reads, the NS, its local data and PTRs",
      re.search(r"^\s*\d+ ; Serial", rpz, re.M) and "@       IN      NS      localhost." in rpz
      and "files.home.arpa CNAME nas.home.arpa." in rpz and "10.20.1.10.in-addr.arpa PTR nas.home.arpa." in rpz, rpz)

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
check("a group with clients in a split subnet gets a view there: its clients inside it (the smaller of each pair)",
      pairs == {"adults-subnet-10-1-10-0-24": ["!10.1.20.64/26", LAN],
                "kids-subnet-10-1-20-0-24": ["10.1.20.64/26"],
                "adults-subnet-10-1-20-0-24": ["!10.1.20.64/26", IOT],
                "adults-subnet-10-1-21-0-24": ["!10.1.20.64/26", IOT2]}, pairs)
check("negative: a group with no client in the subnet gets no such view",
      not any(n.startswith("guests-") for n in pairs) and "kids-subnet-10-1-10-0-24" not in pairs)
check("each split subnet's own view: the subnet, its RPZ", views["subnets"][1] == {
    "name": "subnet-10-1-20-0-24", "match": [IOT], "split": "split-10-1-20-0-24.rpz"}, views["subnets"])
ctx = {**G, "groups": views["groups"], "pairs": views["pairs"], "subnets": views["subnets"], "zones": ["home.arpa"],
       "safe_zone": None, "clients": ["10.1.0.0/16"], "deny": [], "client_tls": False, "adguard_tls": True,
       "ip_bind9": "10.255.0.53", "ip_adguard": "10.255.0.54", "resolver_rndc_secret": "z"}
res = TPL.get_template("resolver/config/named.conf.j2").render(**ctx)
order = [m for m in re.findall(r'^view "([^"]+)"', res, re.M)]
check("the views in order: the pairs, the groups, the subnets, everyone (the most specific wins)",
      order == list(pairs) + ["kids", "adults", "guests", "subnet-10-1-10-0-24", "subnet-10-1-20-0-24",
                              "subnet-10-1-21-0-24", "everyone"], order)
pair = res[res.index('view "kids-subnet-10-1-20-0-24"'):res.index('view "adults-subnet-10-1-20-0-24"')]
check("a pair's view: the group's filtering (its DoT name, rules, safe search) with the subnet's answers first",
      'tls "group-kids"' in pair and 'zone "group-kids.rpz"' in pair
      and 'zone "split-10-1-20-0-24.rpz" { type primary;' in pair
      and pair.index('zone "split-10-1-20-0-24.rpz";') < pair.index('zone "fabric.rpz";'), pair)
own = res[res.index('view "subnet-10-1-20-0-24"'):res.index('view "subnet-10-1-21-0-24"')]
check("the subnet's view: everyone's filtering with its answers first", 'match-clients { 10.1.20.0/24; };' in own
      and own.index('zone "split-10-1-20-0-24.rpz";') < own.index('zone "fabric.rpz";') and "group-" not in own, own)
every = res[res.index('view "everyone"'):]
check("negative: everyone's view has no subnet's answers", "split-" not in every and "match-clients { any; };" in every,
      every)
grp = res[res.index('view "kids"'):res.index('view "adults"')]
check("negative: a group's own view (its clients outside the split subnets) has no subnet's answers",
      "split-" not in grp, grp)
plain_views = resolver_views({**G, "dns": {}}, PLAN)
check("negative: no subnet with answers: no pair and no subnet view", not plain_views["pairs"]
      and not plain_views["subnets"])

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
