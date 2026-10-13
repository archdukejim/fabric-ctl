import re

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.ipam.common.site_scope import site_scope
from fabriclib.ipam.export_plan import export_plan
from fabriclib.ipam.read_plan import read_plan


def networks_csv(v, site="", secrets=None, container="samba"):
    """Purpose: the Networks tab's CSV export (manual 1.10.4.9, 1.10.4.21): one site's address table, as `fabricctl
             ipam export <site>` writes it (export_plan: formula-looking cells defused), with this site's leases.
    Inputs:  v — fabric vars; site — a site this console shows ("" this one); secrets, container — as read_plan.
    Returns: {"csv": str, "name": "<site>-addresses.csv" (letters, digits, dot, dash and underscore only)}.
    Fails:   ValidationError from site_scope or read_plan (the DC not answering: an export is never of a stale copy).
    Feeds:   agent route GET /v1/networks/<site>/export (dhcp:read)."""
    which = site_scope(v, site)
    read = read_plan(v, secrets, of=which, container=container)
    leases = None
    if which == v.get("site_name") and v.get("install_kea"):
        try:
            leases = list_leases(v)
        except (ValidationError, OSError, ValueError):
            leases = None
    name = re.sub(r"[^A-Za-z0-9._-]", "_", which) or "site"
    return {"csv": export_plan(read, which, leases, v.get("site_name") or ""), "name": f"{name}-addresses.csv"}
