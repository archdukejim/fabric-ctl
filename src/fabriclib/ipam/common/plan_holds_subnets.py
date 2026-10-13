import os

from fabriclib.ipam.common.plan_cache import plan_cache_path

# what the 0.7 subnet commands say once the subnets live in the plan (manual 1.10.4.9)
MOVED = ("this site's subnets, their pools and reservations are in the address plan since 0.8.0: change them in "
         "the console's Networks tab or with fabricctl ipam (vlan, subnet, range, address)")
# and what the 0.7 option and class commands say once the global options moved with them (2.1.10.23)
MOVED_OPTIONS = ("the site's DHCP options and client classes are in the address plan since 0.8.0: change them with "
                 "fabricctl ipam option and ipam class")


def plan_holds_subnets(data):
    """Purpose: whether this site's subnets live in the address plan (manual 1.10.4.10): the settings carry no
             `dhcp.subnets` and a plan has been read from the domain.
    Inputs:  data — the settings as saved (vars.yaml).
    Returns: bool.
    Fails:   never.
    Feeds:   dhcp/common/edit_dhcp, dhcp/add_reservation, dhcp/remove_reservation, dhcp/set_dhcp_on (the 0.7
             commands that edited subnets in the settings)."""
    return "subnets" not in (data.get("dhcp") or {}) and os.path.exists(plan_cache_path())
