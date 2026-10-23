#!/usr/bin/env python3
"""The 0.7 (and 0.8.0) DHCP commands once a site's subnets live in the address plan, with no container (manual
1.10.4.21, 1.10.4.37, decision 2.1.10.27; the port's area 4, 1.10.4.41): when the plan holds them, `fabricctl dhcp
add-subnet | set-subnet | remove-subnet | reserve | unreserve` as aliases of `fabricctl ipam` (each routed to its ipam
function, saying so), their refusals that need no domain, and the commands that edited the settings' subnets,
options and classes refused, pointing at `fabricctl ipam`, with nothing saved. The aliases' writes on a real DC:
tests/samba/ipam.py.

    python3 tests/ipam/aliases.py
"""
import io
import os
import sys
import tempfile
from contextlib import contextmanager, redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
W = tempfile.mkdtemp(prefix="fabric-ipam-aliases-")
os.environ["DEPLOY_BASE_DIR"] = W                # the plan's kept copy goes under the test's folder
import fabriclib.dhcp.add_reservation as m_add_res  # noqa: E402
import fabriclib.dhcp.common.edit_dhcp as m_edit_dhcp  # noqa: E402
import fabriclib.dhcp.remove_reservation as m_rm_res  # noqa: E402
import fabriclib.dhcp.run_dhcp_alias as m_alias  # noqa: E402
import fabriclib.dhcp.run_dhcp_command as m_dhcp  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.add_client_class import add_client_class  # noqa: E402
from fabriclib.dhcp.set_option import set_option  # noqa: E402
from fabriclib.ipam.common.fields import KEEP  # noqa: E402
from fabriclib.ipam.common.plan_cache import plan_cache_path, save_plan_cache  # noqa: E402
from fabriclib.ipam.common.plan_holds_subnets import MOVED, MOVED_OPTIONS, plan_holds_subnets  # noqa: E402
from fabriclib.ipam.remove_reservation_mac import remove_reservation_mac  # noqa: E402
from fabriclib.ipam.set_dhcp_subnet import set_dhcp_subnet  # noqa: E402

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:500]}"))


def refused(fn, words):
    try:
        fn()
    except ValidationError as e:
        return words in str(e)
    return False


V = {"site_name": "lan", "dc_name": "dc-0001"}
print("--- whether the plan holds this site's subnets (1.10.4.10)")
check("not before a plan was read: the settings' own (no kept copy)", not os.path.exists(plan_cache_path())
      and plan_holds_subnets({"dhcp": {}}) is False)
save_plan_cache({"site": "lan", "block": 1, "vlans": [], "subnets": [], "networks": [], "domain_options": None,
                 "site_options": {"options": [], "option_defs": [], "client_classes": []}, "read": "now"})
check("a plan read and no dhcp.subnets in the settings: the plan's", plan_holds_subnets({"dhcp": {"interfaces": []}}))
check("the settings still carrying dhcp.subnets (before the upgrade's move): the settings'",
      plan_holds_subnets({"dhcp": {"subnets": []}}) is False)

print("--- the commands that edited the settings, refused once the plan holds them (1.10.4.21)")
SAVED = []
VARS = {"site_name": "lan", "dhcp": {"interfaces": ["eth0"], "options": [{"name": "ntp-servers", "data": "10.1.0.1"}]}}


@contextmanager
def no_lock():
    yield


for m in (m_edit_dhcp, m_add_res, m_rm_res):
    m.vars_lock = no_lock
    m.load_vars = lambda path=None: {k: (dict(x) if isinstance(x, dict) else x) for k, x in VARS.items()}
    m.save_vars = lambda data, path=None: SAVED.append(data)
    m.write_audit = lambda *a, **k: SAVED.append(("audit", a))
check("negative: a global option (fabricctl dhcp option set): refused, naming ipam option; nothing saved",
      refused(lambda: set_option("root", "ntp-servers", "10.1.0.2"), "fabricctl ipam option") and SAVED == [])
check("negative: a client class: refused with the same words", refused(
    lambda: add_client_class("root", "uefi", "option[93].hex == 0x0007"), MOVED_OPTIONS) and SAVED == [])
check("negative: a subnet's option: refused, naming ipam's subnet commands; nothing saved",
      refused(lambda: set_option("root", "ntp-servers", "10.1.0.2", subnet="iot"), MOVED) and SAVED == [])
check("negative: reserve without the alias (add_reservation): refused, nothing saved",
      refused(lambda: m_add_res.add_reservation("root", "aa:bb:cc:dd:ee:01", "10.1.20.150"), MOVED) and SAVED == [])
check("negative: unreserve without the alias (remove_reservation): refused, nothing saved",
      refused(lambda: m_rm_res.remove_reservation("root", "aa:bb:cc:dd:ee:01"), MOVED) and SAVED == [])

print("--- the aliases' own checks, before the domain is asked")
check("negative: set-subnet with nothing to change", refused(lambda: set_dhcp_subnet(V, "root", "iot", router=KEEP),
                                                             "nothing to change"))
check("negative: unreserve with something that is not a MAC", refused(lambda: remove_reservation_mac(V, "root", "nope"),
                                                                       "not a MAC"))
CALLS = []


def recorder(name, result):
    def fn(v, actor, *args, **kw):
        CALLS.append((name, args, kw))
        return {"result": result, "warnings": ["a warning"], "done": ["x"], "site": "lan"}
    return fn


m_alias.add_dhcp_subnet = recorder("add_dhcp_subnet", {"subnet": {"cidr": "10.1.40.0/24", "name": "x"},
                                                       "vlan": {"id": 40}, "vlan_added": True})
m_alias.set_dhcp_subnet = recorder("set_dhcp_subnet", {"name": "iot"})
m_alias.remove_subnet = recorder("remove_subnet", {"subnet": {"cidr": "10.1.20.0/24"}})
m_alias.add_address = recorder("add_address", {"ip": "10.1.20.150", "mac": "aa:bb:cc:dd:ee:01"})
m_alias.remove_reservation_mac = recorder("remove_reservation_mac", {"ip": "10.1.20.150"})
m_alias.apply_dhcp_change = lambda args: CALLS.append(("apply", args)) or 0
m_dhcp.plan_holds_subnets = lambda data: True
m_dhcp.load_vars = lambda: {}


def dhcp(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = m_dhcp.run_dhcp_command(V, list(argv))
    return code, out.getvalue() + err.getvalue()


print("--- the 0.7 commands as aliases of fabricctl ipam (1.10.4.21, 2.1.10.27)")
# covers: cli:dhcp.add-subnet +
del CALLS[:]
code, text = dhcp("add-subnet", "10.1.40.0/24", "--name", "x", "--vlan", "40", "--pool", "10.1.40.100 - 10.1.40.200",
                  "--no-apply")
check("add-subnet: add_dhcp_subnet with its VLAN and pool, saying it is an alias, then applied (--no-apply passed)",
      code == 0 and CALLS[0][0] == "add_dhcp_subnet" and CALLS[0][1][2] == 40
      and CALLS[0][1][4] == ["10.1.40.100 - 10.1.40.200"] and "(alias of fabricctl ipam vlan add" in text
      and "warning: a warning" in text and CALLS[-1] == ("apply", ["10.1.40.0/24", "--name", "x", "--vlan", "40",
                                                                   "--pool", "10.1.40.100 - 10.1.40.200",
                                                                   "--no-apply"]), (CALLS, text))
# covers: cli:dhcp.set-subnet +
del CALLS[:]
code, text = dhcp("set-subnet", "iot", "--router", "none", "--add-pool", "10.1.20.50 - 10.1.20.60")
check("set-subnet: set_dhcp_subnet, `none` clearing the router", code == 0 and CALLS[0][0] == "set_dhcp_subnet"
      and CALLS[0][2]["router"] == "" and CALLS[0][2]["notes"] is KEEP
      and CALLS[0][2]["add_pools"] == ["10.1.20.50 - 10.1.20.60"], CALLS)
# covers: cli:dhcp.remove-subnet +
del CALLS[:]
code, text = dhcp("remove-subnet", "iot", "--force")
check("remove-subnet --force: remove_subnet with its addresses", code == 0 and CALLS[0][0] == "remove_subnet"
      and CALLS[0][1][2] is True, CALLS)
# covers: cli:dhcp.reserve +
del CALLS[:]
code, text = dhcp("reserve", "aa:bb:cc:dd:ee:01", "10.1.20.150", "cam1")
check("reserve: a reservation address with its name and MAC", code == 0 and CALLS[0][0] == "add_address"
      and CALLS[0][1] == ("10.1.20.150", "reservation", "", "cam1", "aa:bb:cc:dd:ee:01"), CALLS)
# covers: cli:dhcp.unreserve +
del CALLS[:]
code, text = dhcp("unreserve", "aa:bb:cc:dd:ee:01")
check("unreserve: remove_reservation_mac", code == 0 and CALLS[0] == ("remove_reservation_mac",
                                                                      ("aa:bb:cc:dd:ee:01",), {}), CALLS)
# covers: cli:dhcp.set-subnet -
del CALLS[:]
code, text = dhcp("set-subnet", "iot", "--name", "cams")
check("negative: set-subnet --name: refused, saying where names change; nothing called", code == 1
      and "stay in the address plan" in text and CALLS == [], (code, text))
# covers: cli:dhcp.add-subnet -
code, text = dhcp("add-subnet", "10.1.40.0/24", "--name", "x", "--vlan", "forty")
check("negative: add-subnet with a VLAN that is not a number", code == 1 and "1 to 4094" in text and CALLS == [],
      (code, text))
code, text = dhcp("add-subnet", "10.1.40.0/24")
check("negative: an alias form it does not know prints the usage (exit 2)", code == 2 and "usage" in text
      and "aliases of fabricctl ipam" in text, (code, text))
# covers: cli:dhcp.remove-subnet -
code, text = dhcp("remove-subnet")
check("negative: remove-subnet without a subnet: usage", code == 2 and CALLS == [], (code, text))
# covers: cli:dhcp.reserve -
code, text = dhcp("reserve", "aa:bb:cc:dd:ee:01")
check("negative: reserve without an address: usage", code == 2 and CALLS == [], (code, text))
# covers: cli:dhcp.unreserve -
m_alias.remove_reservation_mac = remove_reservation_mac
code, text = dhcp("unreserve", "zz")
check("negative: unreserve with a bad MAC (exit 1)", code == 1 and "not a MAC" in text, (code, text))
m_dhcp.plan_holds_subnets = lambda data: False
code, text = dhcp("unreserve")
check("without the plan holding them, the 0.7 commands are their own (unreserve without a MAC: usage)", code == 2
      and CALLS == [], (code, text))

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
