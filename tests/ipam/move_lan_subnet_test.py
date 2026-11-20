#!/usr/bin/env python3
"""The plan's LAN subnet written to the domain at its new network after a restore (ipam/move_lan_subnet; manual
1.3.7.7): the order of the plan's own functions, resuming a run that stopped, crossed off when done. The plan's
functions and the DC stood in for: the real write is the sandbox's move (4.2.4.8).

    python3 tests/ipam/move_lan_subnet_test.py
"""
import copy
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.ipam.move_lan_subnet as mls  # noqa: E402
from fabriclib.backup.restore_pending import read_restore_pending, write_restore_pending  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


LAN = {"name": "lan", "cidr": "10.77.0.0/24", "vlan": 1, "gateway": "10.77.0.1", "dhcp": True,
       "ranges": [{"kind": "dhcp", "first": "10.77.0.200", "last": "10.77.0.220"}],
       "addresses": [{"ip": "10.77.0.40", "kind": "static", "name": "nas", "dns": True}]}
state = {"subnets": []}
calls, fail = [], {"at": None}


def act(name):
    def run(*a, **k):
        calls.append((name, a[2:4] if name != "remove" else a[2]))
        if fail["at"] == name:
            raise ValidationError(f"{name} refused")
        if name == "remove":
            state["subnets"] = [s for s in state["subnets"] if s["cidr"] != a[2]]
        elif name == "subnet":
            state["subnets"].append({"name": k["name"], "cidr": a[3], "vlan": 1, "ranges": [], "addresses": []})
        elif name == "range":
            state["subnets"][-1]["ranges"].append({"kind": a[3], "first": a[4], "last": a[5]})
        elif name == "address":
            state["subnets"][-1]["addresses"].append({"ip": a[2], "kind": a[3]})
    return run


mls.remove_subnet, mls.add_subnet = act("remove"), act("subnet")
mls.add_range, mls.add_address = act("range"), act("address")
mls.read_plan = lambda v, s, of, container: {}
mls.site_plan = lambda read, site: copy.deepcopy(state)
V = {"site_name": "hq"}
config = tempfile.mkdtemp()

check("positive: nothing pending: nothing done", mls.move_lan_subnet(V, config, {}) == [] and not calls)
state["subnets"] = [copy.deepcopy(LAN)]
write_restore_pending(config, {"plan_move": {"from": "10.77.0.0/24", "to": "10.79.0.0/24"}, "signin": "/x"})
lines = mls.move_lan_subnet(V, config, {})
check("positive: the old subnet removed, the new one added to the same VLAN and name, then its range and address",
      [c[0] for c in calls] == ["remove", "subnet", "range", "address"] and calls[1][1] == ("1", "10.79.0.0/24")
      and state["subnets"][0]["cidr"] == "10.79.0.0/24"
      and state["subnets"][0]["ranges"][0]["first"] == "10.79.0.200"
      and state["subnets"][0]["addresses"][0]["ip"] == "10.79.0.40", (calls, state))
check("positive: crossed off, other pending loads kept", read_restore_pending(config) == {"signin": "/x"},
      read_restore_pending(config))
check("positive: what was done is said", any("10.79.0.0/24 added" in x for x in lines), lines)

calls.clear()
state["subnets"] = [copy.deepcopy(LAN)]
write_restore_pending(config, {"plan_move": {"from": "10.77.0.0/24", "to": "10.79.0.0/24"}})
fail["at"] = "range"
try:
    mls.move_lan_subnet(V, config, {})
    stopped = None
except ValidationError as exc:
    stopped = str(exc)
fail["at"] = None
check("negative: a refusal part way: it stops saying why, the move stays pending with the old subnet kept whole",
      stopped == "range refused" and read_restore_pending(config)["plan_move"]["subnet"]["ranges"]
      == LAN["ranges"], read_restore_pending(config))
calls.clear()
mls.move_lan_subnet(V, config, {})
check("positive: the next run goes on: only what is missing is added (not the subnet again)",
      [c[0] for c in calls] == ["range", "address"] and "plan_move" not in read_restore_pending(config), calls)

calls.clear()
state["subnets"] = [{"name": "iot", "cidr": "10.78.0.0/24", "vlan": 20, "ranges": [], "addresses": []}]
write_restore_pending(config, {"plan_move": {"from": "10.77.0.0/24", "to": "10.79.0.0/24"}})
check("positive: no subnet held the old LAN: nothing changed, crossed off",
      mls.move_lan_subnet(V, config, {}) == [] and not calls and read_restore_pending(config) == {}, calls)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
