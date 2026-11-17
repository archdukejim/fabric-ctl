from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp
from fabriclib.ipam.rules.dhcp_allowed import dhcp_allowed


def planned_subnets(v):
    """Purpose: the DHCP subnets a site serves, wherever they are kept: `dhcp.subnets` in the settings while they carry
             them (before the upgrade, and in every rendered apply, which fills them from the plan), else the plan
             this site last read from its DC (manual 1.10.4.14), so the firewall and the Kea tab see the plan's subnets
             between applies.
    Inputs:  v — fabric vars (dhcp).
    Returns: list of dhcp.subnets entries ([] when there are none); from the plan, only those its rules allow dhcp
             (dhcp_allowed, 1.10.4.48.3).
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   dhcp/client_networks (the firewall, BIND's ACL, the resolver), dhcp/dhcp_overview (the Kea tab)."""
    d = v.get("dhcp") or {}
    if "subnets" in d:
        return d.get("subnets") or []
    plan = load_plan_cache()
    return dhcp_allowed(plan_to_dhcp(plan)["subnets"], v, plan) if plan else []
