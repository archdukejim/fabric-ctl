#!/usr/bin/env python3
"""A move or a rename leaves no old address or name in the site's zone (decision 2.1.1.74, known issue 2.3.1.34):
vars.yaml.j2 rendered for real, as render_vars renders it (dns/common/drop_previous_own first), then the settings
changed as 4.2.4 changes them and rendered again. No container: the sandbox and the joined campaign run real applies.

    python3 tests/dns/drop_previous_own_test.py
"""
import copy
import os
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.dns.common.drop_previous_own import drop_previous_own  # noqa: E402

FAILED = 0
ENV = jinja_env(os.path.join(REPO, "templates"))
SECRETS = dict(ca_password="x", rndc_secret="dGVzdC1vbmx5LXJuZGMtc2VjcmV0LTMyLWJ5dGVzISE=",
               keycloak_admin_user="admin", keycloak_admin_password="x", keycloak_db_password="x",
               webui_oidc_secret="x")
BASE = dict(deploy_base_dir="/opt", domain="lan.test", hostname="fab", host_ip="10.88.0.10",
            lan_cidr="10.88.0.0/24", lan_gateway="10.88.0.1", install_keycloak=True, render_date="2026-11-02",
            cert_country="US", cert_province="S", cert_city="C", cert_org="O", cert_ou="IT", ca_name="CA",
            dns={"dynamic_zone_var": {"zone_authority": True,
                                      "A": [{"name": "nas", "ip": "10.88.0.50"}],
                                      "CNAME": [{"name": "files", "canonical": "nas"},
                                                {"name": "wiki", "canonical": "fab"}]}})


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def render(v):
    """One render as render_vars does it: the last render's own names dropped, then vars.yaml.j2."""
    return yaml.safe_load(ENV.get_template("vars.yaml.j2").render(**drop_previous_own({**SECRETS, **v})))


def zone(v):
    z = v["dns"]["dynamic_zone_var"]
    return ({(r["name"], r["ip"]) for r in z.get("A") or []},
            {(r["name"], r["canonical"]) for r in z.get("CNAME") or []})


first = render(copy.deepcopy(BASE))
again = render(copy.deepcopy(first))
check("a render of a render changes nothing (fabric's own list included)", first == again,
      {k: (first.get(k), again.get(k)) for k in set(first) | set(again) if first.get(k) != again.get(k)})
a, c = zone(first)
check("fabric's names are in the zone at the host's address", {("fab", "10.88.0.10"), ("@", "10.88.0.10")} <= a, a)
check("fabric keeps the list of what it added", {r["name"] for r in first["dns_fabric_own"]["A"]} == {"fab", "@"},
      first["dns_fabric_own"])
check("the admin's records are not in fabric's list",
      not ({"nas", "files", "wiki"} & {r["name"] for t in ("A", "CNAME") for r in first["dns_fabric_own"][t]}),
      first["dns_fabric_own"])
check("the landing page's alias is the admin's record, never in fabric's list",
      "info" not in {r["name"] for r in first["dns_fabric_own"]["CNAME"]}, first["dns_fabric_own"])

# a move (4.2.4.2 step 3): host_ip changed in vars.yaml, then an apply
moved = render({**copy.deepcopy(first), "host_ip": "10.88.0.13"})
a, c = zone(moved)
check("after a move: the host and @ at the new address only", {n: ip for n, ip in a if n in ("fab", "@")} ==
      {"fab": "10.88.0.13", "@": "10.88.0.13"} and not any(ip == "10.88.0.10" for _, ip in a), sorted(a))
check("after a move: the admin's record kept", ("nas", "10.88.0.50") in a, sorted(a))
check("after a move: no alias twice", len(c) == len(moved["dns"]["dynamic_zone_var"]["CNAME"]), c)

# a rename (4.2.4.3): hostname changed, then an apply
renamed = render({**copy.deepcopy(moved), "hostname": "core"})
a, c = zone(renamed)
check("after a rename: no A record under the old name", not any(n == "fab" for n, _ in a) and ("core", "10.88.0.13")
      in a, sorted(a))
check("after a rename: fabric's aliases name the new host only, each once",
      not any(t == "fab" for _, t in c) and {("ca", "core"), ("dns", "core"), ("sso", "core")} <= c
      and len(c) == len(renamed["dns"]["dynamic_zone_var"]["CNAME"]), sorted(c))
check("after a rename: the admin's alias of the host (wiki) and the landing alias (info) follow it",
      ("wiki", "core") in c and ("info", "core") in c, sorted(c))
check("after a rename: the admin's alias of another machine kept", ("files", "nas") in c, sorted(c))
check("a render after the rename changes nothing", render(copy.deepcopy(renamed)) == renamed)

# an install that has once been ready: the landing alias is the admin's (2.1.4.6), kept, and follows a rename
ready = render({**copy.deepcopy(first), "hostname_landing": "info.lan.test", "install_was_ready": True})
_, c = zone(ready)
check("once ready: the landing alias stays in the zone", ("info", "fab") in c, sorted(c))
check("once ready: a render of a render changes nothing", render(copy.deepcopy(ready)) == ready)
_, c = zone(render({**copy.deepcopy(ready), "hostname": "core"}))
check("once ready, renamed: the landing alias follows the new name, once", ("info", "core") in c and
      not any(t == "fab" for _, t in c) and sum(1 for n, _ in c if n == "info") == 1, sorted(c))

# an install from before 0.9.2 (no list kept): only exact matches are taken for fabric's (positive evidence)
old = copy.deepcopy(first)
old.pop("dns_fabric_own")
old["dns"]["dynamic_zone_var"]["A"].append({"name": "fab", "ip": "10.88.0.99"})       # not fabric's: kept
up = render(old)
a, _ = zone(up)
check("upgrade with no list: a record that does not match fabric's names exactly is left alone",
      ("fab", "10.88.0.99") in a and ("fab", "10.88.0.10") in a, sorted(a))
check("upgrade with no list: fabric's list written", {r["name"] for r in up["dns_fabric_own"]["A"]} == {"fab", "@"},
      up.get("dns_fabric_own"))
check("upgrade of an unchanged install: the zone is as before", zone(render(copy.deepcopy({**first, "dns_fabric_own":
      None}))) == zone(first))

# covers: setting:dns_fabric_own +
check("an empty list (a render that added nothing) is accepted", render({**copy.deepcopy(first), "dns_fabric_own":
      {"A": [], "CNAME": []}})["dns"] is not None)
# covers: setting:dns_fabric_own -
for bad in ("fab", ["fab"], {"A": "fab"}, {"MX": []}, {"A": ["fab"]}):
    try:
        drop_previous_own({**first, "dns_fabric_own": bad})
        check(f"dns_fabric_own {bad!r} refused", False, "accepted")
    except ValidationError as e:
        check(f"dns_fabric_own {bad!r} refused, saying it is fabric's own record", "fabric's own record" in str(e), e)
try:
    drop_previous_own({"dns_fabric_own": "x"})
    check("a bad list with no zone refused", False, "accepted")
except ValidationError:
    check("a bad list with no zone refused", True)
before = copy.deepcopy(first)
drop_previous_own(first)
check("the caller's settings are not changed", first == before)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
