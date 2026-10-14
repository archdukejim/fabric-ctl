import time

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.common.site_scope import site_scope


def _allowed(value):
    """Purpose: the setting as typed: allow/on/true or deny/off/false.
    Inputs:  value — str or bool.
    Returns: bool.
    Fails:   ValidationError for anything else.
    Feeds:   set_local_scan."""
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in ("allow", "on", "true"):
        return True
    if text in ("deny", "off", "false"):
        return False
    raise ValidationError(f"local scans are allowed or denied: allow or deny, on or off (got {value!r})")


def set_local_scan(v, actor, site, allowed, secrets=None, container="samba", source="cli", edit=edit_options,
                   scope=site_scope):
    """Purpose: whether a site below this one may start scans locally (decision 2.1.10.30, manual 1.10.4.29.4): set only
             from a site above (the Networks tab's scope, and never this site itself), written on the site's OU with who
             set it, at a writable DC, and audited (IPAM_LOCAL_SCAN_SET) through common/edit_options. AD refuses the
             site's own agent and OU admins too (ensure_site_acl). Nothing is applied: the next scan reads it.
    Inputs:  v — fabric vars (site_name, ad_dc_type, ad_join_server); actor — who asks (audit, and the "set by" text);
             site — the site below; allowed — "allow"/"deny", "on"/"off" or bool; secrets, container — as read_plan;
             source — "cli" or "web"; edit, scope — edit_options and site_scope (tests give their own).
    Returns: edit_options' result; its "result": {"site", "allowed" (bool), "set_by"}.
    Fails:   ValidationError: no site named; this site ("set by the sites above it"); a site this install does not see
             below it (site_scope: a sibling, a parent); a value that is neither; the directory refusing ("not
             permitted for this site"); the DC not answering; a read-only DC with no writable partner.
    Feeds:   run_scan_command (local-scan allow|deny), agent POST /v1/ipam/local-scan."""
    own = v["site_name"]
    if not str(site or "").strip():
        raise ValidationError("name the site below this one whose local scans you set (--site S)")
    if str(site).strip().lower() == own.lower():
        raise ValidationError(f"whether {own}'s admins may scan is set by the sites above it, not at {own}")
    target = scope(v, site)
    value = _allowed(allowed)
    by = f"{own} {actor} {time.strftime('%Y-%m-%d %H:%M')}"

    def change(plan):
        result = {"site": target, "allowed": value, "set_by": by}
        return ([{"do": "set", "what": "local_scan", "site": target, "key": target,
                  "fields": {"allowed": value, "by": by}}], result, f"allowed={value}", [])

    return edit(v, actor, target, "IPAM_LOCAL_SCAN_SET", change, secrets, container, source)
