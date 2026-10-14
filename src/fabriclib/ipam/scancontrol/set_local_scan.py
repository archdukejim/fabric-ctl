import time

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.common.site_scope import site_scope


def _allowed(value):
    """Purpose: the setting as typed: allow/on/true, deny/off/false, or clear (the value removed, revised 2026-10-13).
    Inputs:  value — str or bool.
    Returns: bool, or None for clear.
    Fails:   ValidationError for anything else.
    Feeds:   set_local_scan."""
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in ("allow", "on", "true"):
        return True
    if text in ("deny", "off", "false"):
        return False
    if text == "clear":
        return None
    raise ValidationError(f"local scans are allowed, denied or cleared: allow, deny or clear (got {value!r})")


def _outranked(here, entry, site):
    """Purpose: why this site may not change a branch's setting (the owner's answer of 2026-10-13, 2.1.10.30's
             revision): the effective value is the one written by the highest site above the branch that set it, so a
             lower site may set it only where no higher one has. AD cannot express this (an access entry cannot depend
             on who wrote a value), so the agent enforces it; AD only stops the branch itself.
    Inputs:  here — this site; entry — the branch's local_scan as read with its plan ({"set_by", "above"}); site — the
             branch.
    Returns: "" when this site may set it, else the refusal's text naming the site that set it.
    Fails:   never.
    Feeds:   set_local_scan."""
    above = list(entry.get("above") or [])
    setter = str(entry.get("set_by") or "").split(" ", 1)[0]
    if not above or here not in above:
        return f"{here} is not above {site} in the domain: only the sites above {site} set it"
    if setter and setter in above and above.index(setter) > above.index(here):
        return (f"local scans at {site} were set by {setter}, above {here}: only {setter} or a site above it may "
                f"change them ({entry.get('set_by')})")
    return ""


def set_local_scan(v, actor, site, allowed, secrets=None, container="samba", source="cli", edit=edit_options,
                   scope=site_scope):
    """Purpose: whether a site below this one may start scans locally (decision 2.1.10.30, manual 1.10.4.29.4): set only
             from a site above (the Networks tab's scope, and never this site itself), written on the site's OU with who
             set it, at a writable DC, and audited (IPAM_LOCAL_SCAN_SET) through common/edit_options. The highest
             site above that set it wins: a lower one may set it only where no higher one has (_outranked, enforced
             here; revised 2026-10-13). AD refuses the site's own agent and OU admins too (ensure_site_acl). Nothing is
             applied: the next scan reads it. "clear" removes the value (the site that set it or one above it, as for
             a change; nothing set: refused), so the branch is back to the default (off) and a lower site may set
             it again; only one value is kept, so no lower site's earlier value comes back. Audited
             IPAM_LOCAL_SCAN_CLEAR.
    Inputs:  v — fabric vars (site_name, ad_dc_type, ad_join_server); actor — who asks (audit, and the "set by" text);
             site — the site below; allowed — "allow"/"deny", "on"/"off", bool, or "clear"; secrets, container — as
             read_plan; source — "cli" or "web"; edit, scope — edit_options and site_scope (tests give their own).
    Returns: edit_options' result; its "result": {"site", "allowed" (bool, None when cleared), "set_by" ("" when
             cleared)}.
    Fails:   ValidationError: no site named; this site ("set by the sites above it"); a site this install does not see
             below it (site_scope: a sibling, a parent); a value that is neither; a value set by a site higher up
             (naming it), or this site not above the branch in the domain; the directory refusing ("not
             permitted for this site"); the DC not answering; a read-only DC with no writable partner.
    Feeds:   run_scan_command (local-scan allow|deny|clear), agent POST /v1/ipam/local-scan."""
    own = v["site_name"]
    if not str(site or "").strip():
        raise ValidationError("name the site below this one whose local scans you set (--site S)")
    if str(site).strip().lower() == own.lower():
        raise ValidationError(f"whether {own}'s admins may scan is set by the sites above it, not at {own}")
    target = scope(v, site)
    value = _allowed(allowed)
    by = f"{own} {actor} {time.strftime('%Y-%m-%d %H:%M')}"

    def change(plan):
        entry = plan.get("local_scan") or {}
        why = _outranked(own, entry, target)
        if why:
            raise ValidationError(why)
        if value is None and not entry.get("set_by"):
            raise ValidationError(f"local scans at {target} are not set by any site above it: nothing to clear "
                                  "(off by default)")
        by_now = "" if value is None else by
        result = {"site": target, "allowed": value, "set_by": by_now}
        detail = f"cleared (was {entry.get('set_by')})" if value is None else f"allowed={value}"
        return ([{"do": "set", "what": "local_scan", "site": target, "key": target,
                  "fields": {"allowed": value, "by": by_now}}], result, detail, [])

    event = "IPAM_LOCAL_SCAN_CLEAR" if value is None else "IPAM_LOCAL_SCAN_SET"
    return edit(v, actor, target, event, change, secrets, container, source)
