#!/usr/bin/env python3
"""Doctor's checks that a move or a rename left only the host's own address and name (decision 2.1.1.74, manual
4.2.4.7): the answers as BIND gives them after a clean move, and after run 7's defects (2.3.1.33). Pure logic, with a
stand-in for the DNS query; the sandbox and the joined campaign run doctor for real.
    python3 tests/setup/address_checks_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.setup.address_checks import address_checks  # noqa: E402

FAILED = 0
V = {"hostname": "fab", "domain": "lan.test", "host_ip": "10.88.0.13", "hostname_stepca": "ca.lan.test",
     "hostname_dc": "dc-0001.ad.lan.test", "ad_domain": "ad.lan.test",
     "dns_fabric_own": {"A": [{"name": "fab", "ip": "10.88.0.13"}, {"name": "@", "ip": "10.88.0.13"}], "CNAME": []}}


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def run(answers, hosts_text):
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(hosts_text)
    try:
        return address_checks(V, 53, query=lambda name, server, port: answers.get(name, []), hosts=f.name)
    finally:
        os.unlink(f.name)


CLEAN = {n: ["10.88.0.13"] for n in ("fab.lan.test", "lan.test", "ca.lan.test", "dc-0001.ad.lan.test", "ad.lan.test")}
rows = run(CLEAN, "127.0.0.1 localhost\n10.88.0.13 dc-0001.ad.lan.test\n")
check("a clean move: every check passes", rows and all(ok for _, ok, _ in rows), rows)
check("the checks name the host, the site's domain, fabric's alias, the DC, the AD domain and /etc/hosts",
      len(rows) == 6, [r[0] for r in rows])
rows = run(CLEAN, "127.0.0.1 localhost\n")
check("the DC found by DNS, not named in /etc/hosts: passes", all(ok for _, ok, _ in rows), rows)

run7 = {**CLEAN, "fab.lan.test": ["10.88.0.10", "10.88.0.13"], "dc-0001.ad.lan.test": ["10.88.0.10"]}
rows = dict((n, ok) for n, ok, _ in run(run7, "10.88.0.10 dc-0001.ad.lan.test\n10.88.0.13 dc-0001.ad.lan.test\n"))
check("negative: the host's name at the old address too fails", not rows["DNS fab.lan.test: this host at 10.88.0.13 "
      "only (2.1.1.74)"], rows)
check("negative: the DC at the old address alone fails",
      not rows["DNS dc-0001.ad.lan.test: the domain controller at 10.88.0.13 only (2.1.1.74)"], rows)
check("negative: /etc/hosts naming the DC twice (the old line first) fails",
      not rows["/etc/hosts: dc-0001.ad.lan.test at most once, at 10.88.0.13 (2.1.1.74)"], rows)
rows = dict((n, ok) for n, ok, _ in run({**CLEAN, "ad.lan.test": ["10.88.0.10"]}, ""))
check("negative: the AD domain not naming the DC's address fails",
      not rows["DNS ad.lan.test: the AD domain names this DC's address 10.88.0.13 (2.1.1.74)"], rows)
rows = run({}, "")
check("negative: no answer at all fails each DNS check, saying so",
      [d for n, ok, d in rows if n.startswith("DNS")] == ["no answer"] * 5 and not any(ok for n, ok, _ in rows
                                                                                       if n.startswith("DNS")), rows)


def boom(name, server, port):
    raise OSError("timed out")


rows = address_checks(V, 53, query=boom, hosts="/nonexistent")
check("a DNS error is a failed check naming it, never an exception",
      all(not ok and d == "timed out" for n, ok, d in rows if n.startswith("DNS")), rows)
no_own_at = address_checks({**V, "dns_fabric_own": {"A": [], "CNAME": []}}, 53,
                           query=lambda n, s, p: CLEAN.get(n, []), hosts="/nonexistent")
check("an admin's own @ (not fabric's) is not checked", not any(n.startswith("DNS lan.test:") for n, _, _ in no_own_at),
      no_own_at)
plain = address_checks({k: x for k, x in V.items() if k not in ("ad_domain", "hostname_dc")}, 53,
                       query=lambda n, s, p: CLEAN.get(n, []), hosts="/nonexistent")
check("an install with no AD domain: no DC checks", len(plain) == 3, plain)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
