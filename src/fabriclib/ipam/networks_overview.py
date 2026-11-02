from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.networks_view import networks_view
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.scancontrol.list_scan_requests import list_scan_requests
from fabriclib.ipam.sync.sync_status import sync_status


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
            "plans": {site: {k: kept.get(k) or [] for k in ("vlans", "subnets", "networks")}},
            "option_sets": {"domain": kept.get("domain_options"), site: kept.get("site_options")}}
    return read, kept.get("read") or ""


def networks_overview(v, site="", secrets=None, container="samba"):
    """Purpose: what the Networks tab shows (manual 1.10.4.9, 1.10.4.21, 1.10.4.35): one site of the domain's plan,
             read as this site's agent account, drawn by networks_view, with this site's live leases beside it; every
             site of the domain listed (any site may be shown: who may change one is the grants', 1.6.13.12). When
             the DC does not answer, this site's plan as last read is shown, saying so; another site's (or a site
             that is not the domain's) is refused.
    Inputs:  v — fabric vars (site_name, install_kea, dhcp, …); site — the site to show ("" this one); secrets,
             container — as read_plan.
    Returns: networks_view's result plus "own" (this install's site), "stale" (why the kept copy is shown, else ""),
             "error" (why nothing could be read, else ""), "leases_error" ("" or why Kea's leases are missing),
             "scan_requests" (the site shown's scan requests and their answers, list_scan_requests, 1.10.4.36),
             "scan_requests_error" ("" or why they could not be read), "sync" (sync_status for this site, None for
             another: the Sync now card, 2.1.10.29).
    Fails:   ValidationError from read_plan for another site ("no such site: <S>", the DC not answering); OSError
             from the kept copy.
    Feeds:   agent route GET /v1/networks[/<site>] (dhcp:read)."""
    own = v.get("site_name") or ""
    which = str(site or "").strip() or own
    stale, error = "", ""
    try:
        answer = read_plan(v, secrets, of=which, container=container)
    except ValidationError as exc:
        if which != own:
            raise
        answer, when = _cached(own)
        if answer is None:
            error = f"the plan could not be read: {exc}"
            answer = {"sites": [], "plans": {}}
        else:
            stale = f"the domain did not answer ({exc}): this is the plan as last read, at {when}"
    rows, leases_error = None, ""
    if which == own and v.get("install_kea"):
        try:
            rows = list_leases(v)
        except (ValidationError, OSError, ValueError) as exc:
            leases_error = str(exc)
    names = sorted({s["name"] for s in answer.get("sites") or []} | {which})
    out = networks_view(v, answer, which, [{"name": n, "own": n == own} for n in names], rows)
    asked, asked_error = [], ""
    if not error:
        try:
            asked = list_scan_requests(v, which, secrets, container)
        except ValidationError as exc:
            asked_error = str(exc)
    out.update(own=own, stale=stale, error=error, leases_error=leases_error, scan_requests=asked,
               scan_requests_error=asked_error, sync=sync_status(v) if which == own else None)
    return out
