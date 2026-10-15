"""The vars.yaml an apply installs keeps the settings, not what was read from the address plan for the render (manual
1.10.4.14, 2.3.10.10.4): before this, the plan's subnets, option sets and published names were written into vars.yaml,
so the 0.7 `fabricctl dhcp` commands edited them there (and the next apply's upgrade dropped the edit) and a plan name
became a settings record. Pure logic; the sandbox runs real applies.
    python3 tests/deploy/vars_to_save_test.py"""
import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.deploy.vars_to_save import vars_to_save  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


PLAN_SUBNET = {"id": 1, "subnet": "10.77.0.0/24", "name": "lan", "vlan": 1, "pools": ["10.77.0.200 - 10.77.0.220"],
               "reservations": [{"mac": "02:00:00:00:77:01", "ip": "10.77.0.50"}], "interface": "eth0"}
SETTINGS = {"domain": "lan.test", "install_kea": True,
            "dhcp": {"interfaces": ["eth0"], "lease_time": 600},
            "dns": {"dynamic_zone_var": {"zone_authority": True, "A": [{"name": "rerun-test", "ip": "10.77.0.99"}]}}}


def rendered(settings):
    """What check_rendered makes of the settings once the plan holds the subnets (load_address_plan, check_settings)."""
    v = copy.deepcopy(settings)
    v["dhcp"] = {**v["dhcp"], "subnets": [PLAN_SUBNET],
                 "options": [{"name": "domain-name-servers", "data": "10.77.0.10"}],
                 "client_classes": [{"name": "pxe-uefi", "test": "option[93].hex == 0x0007"}]}
    zone = v.setdefault("dns", {}).setdefault("dynamic_zone_var", {})
    zone["A"] = list(zone.get("A") or []) + [{"name": "printer", "ip": "10.77.0.60"}]
    v["dhcp_served"] = True
    v["dhcp_reverse_zones"] = ["0.77.10.in-addr.arpa"]
    return v


out = vars_to_save(rendered(SETTINGS), SETTINGS)
check("the plan's subnets are not written into vars.yaml (plan_holds_subnets stays true)",
      "subnets" not in out["dhcp"], out["dhcp"])
check("the plan's option sets are not written into vars.yaml (the upgrade has nothing to move again)",
      not {"options", "option_defs", "client_classes"} & set(out["dhcp"]), out["dhcp"])
check("the plan's published names are not written as settings records; the settings' own record stays",
      out["dns"]["dynamic_zone_var"]["A"] == [{"name": "rerun-test", "ip": "10.77.0.99"}], out["dns"])
check("the rest is the checked settings: interfaces, lease, zone authority, what check_settings derives",
      out["dhcp"]["interfaces"] == ["eth0"] and out["dhcp"]["lease_time"] == 600
      and out["dns"]["dynamic_zone_var"]["zone_authority"] is True and out["dhcp_served"] is True
      and out["dhcp_reverse_zones"] == ["0.77.10.in-addr.arpa"], out)
r = rendered(SETTINGS)
before = copy.deepcopy(r)
vars_to_save(r, SETTINGS)
check("the rendered settings themselves are untouched (the templates render the plan)", r == before)

# settings that still carry their subnets (before the upgrade, or a read-only DC: 2.1.10.19) keep them as placed
old = copy.deepcopy(SETTINGS)
old["dhcp"]["subnets"] = [{"subnet": "10.77.0.0/24", "pools": ["10.77.0.200 - 10.77.0.220"]}]
old["dhcp"]["options"] = [{"name": "ntp-servers", "data": "10.77.0.10"}]
out = vars_to_save(rendered(old), old)
check("settings that still carry subnets keep them, checked and placed (their ids kept)",
      out["dhcp"]["subnets"] == [PLAN_SUBNET], out["dhcp"])
check("...and their own options, without the plan's laid over them",
      out["dhcp"]["options"] == [{"name": "ntp-servers", "data": "10.77.0.10"}]
      and "client_classes" not in out["dhcp"], out["dhcp"])

# a zone the settings never had: the plan's names alone made it
bare = {"domain": "lan.test", "install_kea": True, "dhcp": {"interfaces": ["eth0"]}}
out = vars_to_save(rendered(bare), bare)
check("no dns in the settings: none written (the plan's names alone made the zone's entry)", "dns" not in out, out)
noa = {**bare, "dns": {"dynamic_zone_var": {"zone_authority": True}}}
out = vars_to_save(rendered(noa), noa)
check("a zone without records of its own keeps none", out["dns"]["dynamic_zone_var"] == {"zone_authority": True},
      out["dns"])
off = {"domain": "lan.test", "install_kea": False}
check("DHCP off and no zone: nothing to take out", vars_to_save(dict(off), off) == off)

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
