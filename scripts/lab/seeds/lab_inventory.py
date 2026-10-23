"""The lab's inventory (scripts/lab/lab_vms.json) and the facts derived from it: each NIC's static MAC.

Purpose: one place that reads lab_vms.json for the seed generator (manual 3.1.5.3).
Inputs: the path of lab_vms.json.
Returns: the parsed inventory; mac() gives a NIC's MAC as new_hyperv_lab.ps1 sets it.
Fails: on a missing or malformed file (json raises).
Feeds: make_seeds.py and every *_seed.py.
"""
import json


def load_inventory(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def mac(vm, n, sep=":"):
    """02-88-00-<last octet of the VM's address>-00-<n>, as new_hyperv_lab.ps1's Mac function."""
    octet = int(vm["ip"].split(".")[3])
    parts = ["02", "88", "00", "%02x" % octet, "00", "%02x" % int(n)]
    return sep.join(parts)


def extra_nics(inv, vm_name):
    return [n for n in inv["nics"] if n["vm"] == vm_name]
