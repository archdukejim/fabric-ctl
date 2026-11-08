#!/usr/bin/env python3
"""ubuntu_seed (manual 3.1.5.3, 3.1.5.14): the autoinstall's network. A VM with its own `wan` NIC (the build VM,
decision 2.1.1.99) takes DHCP and its default route there, its lab NIC keeping only the lab's subnet; every other
VM keeps the lab NIC with the router as its way out. Pure: reads the real inventory, writes nothing."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(HERE, "..", "..", "scripts", "lab", "seeds")
sys.path.insert(0, SEEDS)
from lab_inventory import mac  # noqa: E402
from ubuntu_seed import user_data  # noqa: E402

FAILED = 0
PASSED = 0


def check(name, cond, detail=""):
    global FAILED, PASSED
    FAILED += not cond
    PASSED += bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


with open(os.path.join(SEEDS, "..", "lab_vms.json")) as f:
    INV = json.load(f)
VMS = {v["name"]: v for v in INV["vms"]}


def network(name):
    text = user_data(INV, VMS[name], "ssh-ed25519 AAAA test")
    return json.loads(text.split("\n", 1)[1])["autoinstall"]["network"]["ethernets"]


dev = network("g23-vm-dev-1")
check("the build VM is in the inventory, on the lab at 10.88.0.5", VMS["g23-vm-dev-1"]["ip"] == "10.88.0.5", VMS)
check("the build VM's wan NIC takes DHCP, matched by its own MAC",
      dev.get("wan", {}).get("dhcp4") is True
      and dev["wan"]["match"]["macaddress"] == mac(VMS["g23-vm-dev-1"], 2), dev)
check("its lab NIC keeps the lab address but no default route or DNS (the way out is wan)",
      dev["lab"]["addresses"] == ["10.88.0.5/24"] and "routes" not in dev["lab"] and "nameservers" not in dev["lab"],
      dev)
check("it installs what the gate, the suites and the builds need, and qemu-user-static for the arm64 spike",
      {"docker.io", "docker-buildx", "git", "python3-yaml", "dpkg-dev", "qemu-user-static"}
      <= set(VMS["g23-vm-dev-1"].get("packages", [])), VMS["g23-vm-dev-1"])

ub = network("g23-vm-ub26-1")
check("negative: a VM without a wan NIC keeps the router as its default route, and has no wan",
      "wan" not in ub and ub["lab"]["routes"] == [{"to": "default", "via": INV["network"]["gateway"]}], ub)
rtr = network("g23-vm-rtr-1")
check("negative: the router keeps its own netplan (its wan from router_files, not this case)",
      "wan" in rtr and "vlans" in rtr, rtr)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
