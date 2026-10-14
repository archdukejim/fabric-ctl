from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.common.plan_subnets import plan_subnets

LARGEST = 1022          # a /22's hosts: a larger network is not scanned at once (decision 2.1.10.26)


def scannable_subnets(v, cache=load_plan_cache):
    """Purpose: the subnets an on-request scan may cover (manual 1.10.4.22, 1.10.4.27.1; decisions 2.1.10.26 and
             2.1.10.28): every subnet of this site's plan, DHCP on or off (and 0.7's served subnets before the
             upgrade), each no larger than a /22; none where Kea is not installed (the scan runs in its container).
             Who may scan is asked apart (scancontrol/read_local_scan, or a request from above, 2.1.10.30).
    Inputs:  v — fabric vars (install_kea, dhcp, site_name; the plan this site last read); cache — as plan_subnets.
    Returns: list of {"name", "cidr", "vlan", "dhcp" (bool), "hosts"} in address order ([] with DHCP off).
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   agent GET /v1/ipam/scan (the console's scan page)."""
    if not v.get("install_kea"):
        return []
    return [{k: s[k] for k in ("name", "cidr", "vlan", "dhcp", "hosts")} for s in plan_subnets(v, cache)
            if s["hosts"] <= LARGEST]
