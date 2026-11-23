#!/usr/bin/env python3
"""Which address may be announced as the host's next (move/check_new_address; manual 4.2.4.2, 4.2.4.8; decision
2.1.1.79): on the LAN, or on another network named with --network for a move to another VLAN and subnet. Pure logic;
the announce itself is tests/samba/linux_join.py's.

    python3 tests/move/check_new_address_test.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.move.check_new_address import check_new_address  # noqa: E402

FAILED = 0
V = {"host_ip": "10.77.0.10", "lan_cidr": "10.77.0.0/24", "lan_gateway": "10.77.0.1"}


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def why(address, network=None, registry=None):
    try:
        check_new_address(V, address, registry if registry is not None else {}, network)
    except ValidationError as exc:
        return str(exc)
    return None


check("positive: an address on the LAN", check_new_address(V, "10.77.0.13", {}) == "10.77.0.13")
check("positive: an address on another subnet, its network named (4.2.4.8)",
      check_new_address(V, "10.79.0.10", {}, "10.79.0.0/24") == "10.79.0.10")
check("negative: off the LAN without --network: refused, saying how to name the new subnet",
      "--network <new subnet>" in (why("10.79.0.10") or ""), why("10.79.0.10"))
check("negative: an address outside the network named", "is not in --network" in (why("10.80.0.5", "10.79.0.0/24")
                                                                                   or ""))
check("negative: --network that is not a network", "not an IPv4 network" in (why("10.79.0.10", "vlan20") or ""))
check("negative: --network that is the LAN itself or overlaps it",
      "overlaps it" in (why("10.77.0.13", "10.77.0.0/16") or ""), why("10.77.0.13", "10.77.0.0/16"))
check("negative: the new network's own network or broadcast address",
      "network or broadcast" in (why("10.79.0.0", "10.79.0.0/24") or "")
      and "network or broadcast" in (why("10.79.0.255", "10.79.0.0/24") or ""))
check("negative: linked sites: a move to another network is refused as well",
      "linked sites" in (why("10.79.0.10", "10.79.0.0/24", {"sites": {"branch": {}}}) or ""))
check("negative: not an address", "not an IPv4 address" in (why("fabric-2") or ""))
PLANS = [{"name": "lan", "cidr": "10.77.0.0/24"}, {"name": "iot", "cidr": "10.79.0.0/24"}]


def collides(address, network, v=V):
    try:
        check_new_address(v, address, {}, network, plans=PLANS)
    except ValidationError as exc:
        return str(exc)
    return None


check("positive: another network colliding with nothing in the plan (2.1.1.107)",
      collides("10.80.0.10", "10.80.0.0/24") is None)
err = collides("10.79.0.10", "10.79.0.0/24")
check("negative: --network that is another VLAN's subnet in the plan: refused before anything is announced",
      err and "10.79.0.0/24 (iot)" in err, err)
err = collides("10.255.0.10", "10.255.0.0/24")
check("negative: --network that is fabric's container network: refused", err and "fabric_subnet" in err, err)
err = collides("10.254.0.10", "10.254.0.0/24", dict(V, fabric_subnet="10.254.0.0/24"))
check("negative: ...the container network as the settings set it", err and "10.254.0.0/24" in err, err)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
