import re

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.ipam.export_plan import export_plan
from fabriclib.ipam.read_plan import read_plan


def networks_csv(v, site="", secrets=None, container="samba"):
    """Purpose: the Networks tab's CSV export (manual 1.10.4.9, 1.10.4.21, 1.10.4.35): one site's address table, as
             `fabricctl ipam export <site>` writes it (export_plan: formula-looking cells defused), with this site's
             leases. Any site of the domain.
    Inputs:  v — fabric vars; site — the site ("" this one); secrets, container — as read_plan.
    Returns: {"csv": str, "name": "<site>-addresses.csv" (letters, digits, dot, dash and underscore only)}.
    Fails:   ValidationError from read_plan ("no such site: <S>", the DC not answering: an export is never of a stale
             copy).
    Feeds:   agent route GET /v1/networks/<site>/export (dhcp:read)."""
    own = v.get("site_name") or ""
    which = str(site or "").strip() or own
    answer = read_plan(v, secrets, of=which, container=container)
    rows = None
    if which == own and v.get("install_kea"):
        try:
            rows = list_leases(v)
        except (ValidationError, OSError, ValueError):
            rows = None
    name = re.sub(r"[^A-Za-z0-9._-]", "_", which) or "site"
    return {"csv": export_plan(answer, which, rows, own), "name": f"{name}-addresses.csv"}
