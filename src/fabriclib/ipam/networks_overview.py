from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.common.site_scope import site_scope
from fabriclib.ipam.networks_view import networks_view
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.visible_sites import visible_sites


def _cached(site):
    """Purpose: this site's plan as last read (the DC not answering), shaped like read_plan's answer.
    Inputs:  site — this install's site.
    Returns: (read_plan-shaped dict, when it was read), or (None, "") without a kept copy.
    Fails:   OSError or json errors from load_plan_cache.
    Feeds:   networks_overview."""
    kept = load_plan_cache()
    if not kept or kept.get("site") != site:
        return None, ""
    read = {"sites": [{"name": site, "created": "", "block": kept.get("block")}],
            "plans": {site: {k: kept.get(k) or [] for k in ("vlans", "subnets", "networks")}}}
    return read, kept.get("read") or ""


def networks_overview(v, site="", secrets=None, container="samba"):
    """Purpose: what the Networks tab shows (manual 1.10.4.9, 1.10.4.21): one site's plan, read from the domain as
             this site's agent account, drawn by networks_view, with this site's live leases beside it; the sites this
             console may show (visible_sites). When the DC does not answer, this site's plan as last read is shown,
             saying so; another site's is then an error to show.
    Inputs:  v — fabric vars (site_name, install_kea, dhcp, …); site — the site to show ("" this one); secrets,
             container — as read_plan.
    Returns: networks_view's result plus "own" (this install's site), "stale" (why the kept copy is shown, else ""),
             "error" (why nothing could be read, else ""), "leases_error" ("" or why Kea's leases are missing).
    Fails:   ValidationError from site_scope (a site this console does not show); OSError from the kept copy.
    Feeds:   agent route GET /v1/networks[/<site>] (dhcp:read)."""
    own = v.get("site_name") or ""
    which = site_scope(v, site)
    sites = visible_sites(v)
    stale, error = "", ""
    try:
        read = read_plan(v, secrets, of=which, container=container)
    except ValidationError as exc:
        read, when = _cached(which) if which == own else (None, "")
        if read is None:
            error = f"the plan could not be read: {exc}"
            read = {"sites": [], "plans": {}}
        else:
            stale = f"the domain did not answer ({exc}): this is the plan as last read, at {when}"
    leases, leases_error = None, ""
    if which == own and v.get("install_kea"):
        try:
            leases = list_leases(v)
        except (ValidationError, OSError, ValueError) as exc:
            leases_error = str(exc)
    out = networks_view(v, read, which, sites, leases)
    out.update(own=own, stale=stale, error=error, leases_error=leases_error)
    return out
