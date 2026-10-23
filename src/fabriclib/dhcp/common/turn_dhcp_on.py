import copy

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp
from fabriclib.dhcp.place_subnets import place_subnets
from fabriclib.ipam.common.plan_holds_subnets import plan_holds_subnets
from fabriclib.ipam.planned_subnets import planned_subnets


def turn_dhcp_on(data, interface, subnet, pool, router, networks):
    """Purpose: the `dhcp` settings DHCP is turned on with (manual 1.10.3.5), checked and not saved: with its settings
             kept from before, as they were; with none, a first subnet on the interface given; once the subnets live in
             the address plan (manual 1.10.4.9), the plan's (only the interface may be given).
    Inputs:  data — the settings as saved (vars.yaml: dhcp, host_ip, ...); interface, subnet (a network), pool
             ("a - b"), router (optional) — the first subnet when DHCP has none yet; networks — host_networks(), where
             the subnet must lie.
    Returns: the `dhcp` value to save (with the plan's subnets: without them, as the settings keep it).
    Fails:   ValidationError: no settings and no interface, subnet or pool given; what normalize_dhcp or place_subnets
             refuses (an interface the host lacks, a subnet not on it, a bad pool); the subnets in the address plan
             and none of them served by DHCP. OSError or json errors reading the plan's copy.
    Feeds:   dhcp/set_dhcp_on (`fabricctl dhcp on`, POST /v1/dhcp/on); the wizard's DHCP step joins in area 8 of the
             port (1.10.4.41)."""
    dhcp = copy.deepcopy(data.get("dhcp") or {})
    if plan_holds_subnets(data):            # the subnets are the plan's (1.10.4.9): checked, never saved here
        if interface:
            dhcp["interfaces"] = [interface]
        served = {**dhcp, "subnets": planned_subnets(data)}
        if not served["subnets"]:
            raise ValidationError("the address plan has no subnet served by DHCP yet: add one with "
                                  "fabricctl ipam vlan add")
        served = normalize_dhcp({**data, "dhcp": served, "install_kea": True})
        place_subnets(served, data.get("host_ip"), networks)
        return dhcp
    if not dhcp.get("subnets"):
        if not (interface and subnet and pool):
            raise ValidationError("DHCP has no settings yet: give the interface, the subnet and a pool")
        dhcp = {**dhcp, "interfaces": [interface],
                "subnets": [{"subnet": subnet, "pools": [pool], **({"routers": router} if router else {})}]}
    dhcp = normalize_dhcp({**data, "dhcp": dhcp, "install_kea": True})
    place_subnets(dhcp, data.get("host_ip"), networks)
    return dhcp
