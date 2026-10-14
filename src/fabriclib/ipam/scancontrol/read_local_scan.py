from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.scancontrol.local_scan_state import local_scan_state


def read_local_scan(v, site="", secrets=None, container="samba", read=read_plan, cache=load_plan_cache):
    """Purpose: whether a site's own admins may scan there (decision 2.1.10.30, manual 1.10.4.29.4), read from this
             site's DC as its agent; when the DC does not answer, this site's as last read with its plan (the copy every
             read keeps, 1.10.4.14), saying so. With neither it cannot be known: refused, so no local scan runs against
             a setting nobody could read (secure by default).
    Inputs:  v — fabric vars (site_name); site — the site ("" this one); secrets, container — as read_plan; read,
             cache — read_plan and load_plan_cache (tests give their own).
    Returns: local_scan_state's result, plus "stale" ("" when read from the DC, else why and when the kept copy was
             read).
    Fails:   ValidationError "whether local scans are allowed cannot be read …" (the DC not answering and no kept copy
             of this site's; another site's while the DC does not answer); OSError or json errors from a damaged kept
             copy.
    Feeds:   scan_subnet (before anything is probed), scan_overview (GET /v1/ipam/scan), run_scan_command
             (local-scan)."""
    own = v.get("site_name") or ""
    site = site or own
    try:
        levels, stale = (read(v, secrets, of=site, container=container) or {}).get("local_scan") or {}, ""
    except ValidationError as exc:
        kept = cache() if site == own else None
        if not kept or not isinstance(kept.get("local_scan"), dict):
            raise ValidationError(f"whether local scans are allowed at {site} cannot be read ({exc}), and this site "
                                  "keeps no copy of it: no local scan runs until it can be read (start the DC: sudo "
                                  "systemctl start samba)")
        levels = {site: kept["local_scan"]}
        stale = f"the domain did not answer ({exc}): the setting as last read, at {kept.get('read') or '?'}"
    out = local_scan_state(levels, site)
    out["stale"] = stale
    return out
