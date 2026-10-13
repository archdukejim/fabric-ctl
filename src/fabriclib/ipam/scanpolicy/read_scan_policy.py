from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.scanpolicy.effective_scan_policy import effective_scan_policy


def read_scan_policy(v, site="", secrets=None, container="samba", read=read_plan, cache=load_plan_cache):
    """Purpose: the scan policy in force at a site (decision 2.1.10.28, manual 1.10.4.27.4), read from this site's DC as
             its agent; when the DC does not answer, this site's as last read with its plan (the copy every read
             keeps, 1.10.4.14), saying so. With neither, it cannot be known: refused, so no scan runs against a
             policy nobody could read (secure by default).
    Inputs:  v — fabric vars (site_name); site — the site ("" this one); secrets, container — as read_plan; read,
             cache — read_plan and load_plan_cache (tests give their own).
    Returns: effective_scan_policy's result, plus "stale" ("" when read from the DC, else why and when the kept copy
             was read).
    Fails:   ValidationError "the scan policy cannot be read …" (the DC not answering and no kept copy of this site's;
             another site's while the DC does not answer); OSError or json errors from a damaged kept copy.
    Feeds:   scan_subnet (before anything is probed), agent GET /v1/ipam/scan, run_scan_policy_command (show)."""
    own = v.get("site_name") or ""
    site = site or own
    try:
        levels, stale = (read(v, secrets, of=site, container=container) or {}).get("scan_policy") or {}, ""
    except ValidationError as exc:
        kept = cache() if site == own else None
        if not kept or "scan_policy" not in kept:
            raise ValidationError(f"the scan policy cannot be read ({exc}), and this site keeps no copy of it: no scan "
                                  "runs until it can be read (start the DC: sudo systemctl start samba)")
        levels = kept["scan_policy"]
        stale = f"the domain did not answer ({exc}): the scan policy as last read, at {kept.get('read') or '?'}"
    out = effective_scan_policy(levels, site)
    out["stale"] = stale
    return out
