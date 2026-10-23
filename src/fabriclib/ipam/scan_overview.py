from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.ipam.scannable_subnets import scannable_subnets


def scan_overview(v, caller=None, container="samba"):
    """Purpose: what the console's scan page shows before a scan (manual 1.10.4.22.4, 1.10.4.36): the subnets a scan
             may cover, and whether the signed-in person may scan here (the grants' `networks:scan` at this site,
             decision 2.1.10.38), with why not.
    Inputs:  v — fabric vars (install_kea, dhcp, site_name); caller — the signed-in person's user name, or None
             (root); container — the DC's container.
    Returns: {"site", "subnets": scannable_subnets' list, "may" (bool), "why" ("" or why a scan is refused here:
             check_access's refusal, the DC not running)}.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   agent GET /v1/ipam/scan."""
    site = v.get("site_name") or ""
    try:
        check_access(v, caller, "networks:scan", {"site": site}, container)
        may, why = True, ""
    except ValidationError as exc:
        may, why = False, str(exc)
    return {"site": site, "subnets": scannable_subnets(v), "may": may, "why": why}
