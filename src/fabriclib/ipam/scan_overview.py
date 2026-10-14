from fabriclib.common.errors import ValidationError
from fabriclib.ipam.scancontrol.read_local_scan import read_local_scan
from fabriclib.ipam.scannable_subnets import scannable_subnets


def scan_overview(v, local=read_local_scan):
    """Purpose: what the console's scan page shows before a scan (manual 1.10.4.22.4, 1.10.4.29.5): the subnets a scan
             may cover, and whether this site's own admins may scan here, with who set it (2.1.10.30).
    Inputs:  v — fabric vars (install_kea, dhcp, site_name); local — read_local_scan (tests give their own).
    Returns: {"subnets": scannable_subnets' list, "local": read_local_scan's result or None, "local_error": "" or why
             it could not be read (no local scan runs then)}.
    Fails:   OSError or json errors reading a damaged plan copy.
    Feeds:   agent GET /v1/ipam/scan."""
    try:
        return {"subnets": scannable_subnets(v), "local": local(v), "local_error": ""}
    except ValidationError as exc:
        return {"subnets": scannable_subnets(v), "local": None, "local_error": str(exc)}
