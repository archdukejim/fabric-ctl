#!/usr/bin/env python3
"""802.1X on the address plan (manual 1.11.1.7, 1.11.1.8; notes 2.3.11.6), pure logic, no containers: a reservation's
device role (only a reservation names one; the role must exist here; warnings for a role without network:mab or on
another VLAN), a role's VLAN checked against the plan, and the plan's VLAN labels.

    python3 tests/ipam/role_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.common.check_role_vlan import check_role_vlan  # noqa: E402
from fabriclib.ipam.check_address import check_address  # noqa: E402
from fabriclib.ipam.check_address_role import check_address_role  # noqa: E402
from fabriclib.ipam.plan_rows import COLUMNS  # noqa: E402
from fabriclib.ipam.vlan_labels import vlan_labels  # noqa: E402

FAILED = 0
V = {"site_name": "lan"}
SUBNET = {"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "gateway": "10.1.20.1", "dhcp": True,
          "ranges": [{"kind": "dhcp", "first": "10.1.20.100", "last": "10.1.20.199"}], "addresses": []}
PLAN = {"site": "lan", "vlans": [{"id": 20, "name": "iot"}, {"id": 30, "name": "printers"}, {"id": 40, "name": ""}],
        "subnets": [SUBNET, {"name": "printers", "cidr": "10.1.30.0/24", "vlan": 30, "addresses": [], "ranges": []}]}
ROLES = [{"name": "iot", "permissions": ["network:mab"], "vlan": 20},
         {"name": "laptops", "permissions": ["network:eap-tls"], "vlan": None},
         {"name": "printers", "permissions": ["network:mab"], "vlan": 30}]


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def refused(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except ValidationError as exc:
        return str(exc)
    return ""


def reservation(**kw):
    return {"ip": "10.1.20.150", "kind": "reservation", "mac": "AA-BB-CC-DD-EE-FF", "name": "cam1", **kw}


# ------------------------------------------------------------------ a reservation's role (1.11.1.7)
# covers: cli:ipam.address +
addr, warnings = check_address(reservation(role=" IoT "), SUBNET, PLAN)
check("a reservation names a device role: kept lower-case, beside its MAC",
      addr["role"] == "iot" and addr["mac"] == "aa:bb:cc:dd:ee:ff" and not warnings, (addr, warnings))
addr, _ = check_address(reservation(), SUBNET, PLAN)
check("a reservation without a role has role \"\" (the policy refuses it by MAB: no role)", addr["role"] == "", addr)
# covers: cli:ipam.address -
check("a role on a static address is refused, saying how to clear it",
      "only a reservation names a device role" in refused(check_address, {"ip": "10.1.20.10", "kind": "static",
                                                                           "role": "iot"}, SUBNET, PLAN)
      and "--role none" in refused(check_address, {"ip": "10.1.20.10", "kind": "static", "role": "iot"}, SUBNET,
                                   PLAN))
check("a role name that is not one is refused",
      "lowercase letters" in refused(check_address, reservation(role="i o t"), SUBNET, PLAN))

check("check_address_role: no role, nothing to check",
      check_address_role(V, {"ip": "10.1.20.150", "role": ""}, SUBNET, "lan", ROLES) == [])
check("check_address_role: a role that fits (network:mab, the subnet's VLAN) has no warning",
      check_address_role(V, {"ip": "10.1.20.150", "role": "iot"}, SUBNET, "lan", ROLES) == [])
check("check_address_role: a role the directory does not have is refused, naming the roles there are",
      "no device role named cameras" in refused(check_address_role, V, {"ip": "10.1.20.150", "role": "cameras"},
                                               SUBNET, "lan", ROLES)
      and "iot, laptops, printers" in refused(check_address_role, V, {"ip": "10.1.20.150", "role": "cameras"},
                                              SUBNET, "lan", ROLES))
w = check_address_role(V, {"ip": "10.1.20.150", "role": "laptops"}, SUBNET, "lan", ROLES)
check("check_address_role: a role without network:mab is warned about (refused by MAB until it does)",
      len(w) == 1 and "does not grant network:mab" in w[0], w)
w = check_address_role(V, {"ip": "10.1.20.150", "role": "printers"}, SUBNET, "lan", ROLES)
check("check_address_role: a role on another VLAN is warned about: the device goes on the subnet's VLAN",
      len(w) == 1 and "names VLAN 30" in w[0] and "put on VLAN 20" in w[0], w)
w = check_address_role(V, {"ip": "10.1.20.150", "role": "cameras"}, SUBNET, "branch", ROLES)
check("check_address_role: another site's reservation is warned about, its roles not read here",
      len(w) == 1 and "branch's to check" in w[0], w)
check("the address table's CSV has a role column, last (the columns before it unchanged)",
      COLUMNS[-1] == "role" and COLUMNS[:6] == ("site", "vlan", "vlan_name", "subnet", "ip", "kind"), COLUMNS)

# ------------------------------------------------------------------ a role's VLAN (1.11.1.8)
check("check_role_vlan: no VLAN, or a VLAN of the plan, is accepted",
      check_role_vlan(V, None, PLAN) is None and check_role_vlan(V, 30, PLAN) is None)
check("check_role_vlan: a plan without VLANs keeps bare numbers",
      check_role_vlan(V, 99, {"site": "lan", "vlans": [], "subnets": []}) is None)
msg = refused(check_role_vlan, V, 99, PLAN)
check("check_role_vlan: a VLAN outside the plan is refused, naming the plan's VLANs and how to add one",
      "VLAN 99 is not in lan's address plan" in msg and "20 (iot), 30 (printers), 40" in msg
      and "fabricctl ipam vlan add" in msg, msg)

# ------------------------------------------------------------------ labels
labels = vlan_labels(PLAN)
check("vlan_labels: name and subnets per VLAN; a VLAN without a name or subnet is labelled by what it has",
      labels == {"20": "iot, 10.1.20.0/24", "30": "printers, 10.1.30.0/24", "40": ""}, labels)
check("vlan_labels: no plan kept, no labels", vlan_labels(None) == {} and vlan_labels({}) == {})

print()
print("FAILED: %d" % FAILED if FAILED else "all passed")
sys.exit(1 if FAILED else 0)
