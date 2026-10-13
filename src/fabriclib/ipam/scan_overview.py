from fabriclib.common.errors import ValidationError
from fabriclib.ipam.scannable_subnets import scannable_subnets
from fabriclib.ipam.scanpolicy.read_scan_policy import read_scan_policy


def scan_overview(v, policy=read_scan_policy):
    """Purpose: what the console's scan page shows before a scan (manual 1.10.4.22.4, 1.10.4.27.5): the subnets a scan
             may cover, and the scan policy in force here with where it comes from.
    Inputs:  v — fabric vars (install_kea, dhcp, site_name); policy — read_scan_policy (tests give their own).
    Returns: {"subnets": scannable_subnets' list, "policy": read_scan_policy's result or None, "policy_error": "" or
             why the policy could not be read (no scan runs then)}.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   agent GET /v1/ipam/scan."""
    try:
        return {"subnets": scannable_subnets(v), "policy": policy(v), "policy_error": ""}
    except ValidationError as exc:
        return {"subnets": scannable_subnets(v), "policy": None, "policy_error": str(exc)}
