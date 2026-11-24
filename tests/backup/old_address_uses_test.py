#!/usr/bin/env python3
"""What still names the old address or subnet after a move (backup/old_address_uses; manual 1.3.7.7): pure logic.

    python3 tests/backup/old_address_uses_test.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.old_address_uses import old_address_uses  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


V = {"host_ip": "10.0.5.2", "lan_cidr": "10.0.5.0/24", "lan_gateway": "10.0.5.1",
     "dns_fabric_own": {"A": {"ns": "10.0.0.5"}}, "bind_acls": {"dns-resolvers": ["10.0.0.0/24", "10.0.5.0/24"]},
     "dns": {"lab.test": {"A": {"www": "10.0.0.5", "nas": "10.0.0.40", "far": "192.0.2.7", "new": "10.0.5.9"}}},
     "dhcp": {"subnets": [{"subnet": "10.0.0.0/24", "pools": ["10.0.0.100-10.0.0.200"]}]},
     "radius_clients": [{"name": "ap", "address": "10.0.0.0/28"}], "security": {"firewall_allow": ["10.0.0.7"]},
     "dns_server": "10.0.0.1", "extra_certs": [{"sans": ["nas.lab.test", "10.0.0.40"]}], "note": "not an address",
     "fabric_subnet": "172.30.0.0/24"}
found = dict(old_address_uses(V, "10.0.0.5", "10.0.0.0/24"))
check("positive: the admin's records at the old address or in the old subnet are listed",
      found.get("dns.lab.test.A.www") == "10.0.0.5" and found.get("dns.lab.test.A.nas") == "10.0.0.40", found)
check("positive: DHCP's old subnet, a RADIUS client range, a firewall allowance, the upstream DNS server and an "
      "extra certificate's address are listed",
      {"dhcp.subnets.0.subnet", "radius_clients.0.address", "security.firewall_allow.0", "dns_server",
       "extra_certs.0.sans.1"} <= set(found), found)
check("negative: fabric's own (rendered again), the change itself, other networks and text are not listed",
      not any(k.startswith(("dns_fabric_own", "bind_acls", "host_ip", "lan_")) for k in found)
      and "dns.lab.test.A.far" not in found and "dns.lab.test.A.new" not in found and "note" not in found
      and "fabric_subnet" not in found, found)
check("negative: a pool written as a range is not read as an address", "dhcp.subnets.0.pools.0" not in found, found)
check("positive: nothing names the old address: an empty list",
      old_address_uses({"dns": {"z": {"A": {"a": "192.0.2.1"}}}}, "10.0.0.5", "10.0.0.0/24") == [])
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
