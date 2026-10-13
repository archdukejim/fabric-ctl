from fabriclib.common.errors import ValidationError


def refuse_at_read_only_dc(v, what):
    """Purpose: refuse a change that only a writable DC's own copy can take — Group Policy, and who may sign in per OU
             (its log-on GPOs) — at a site whose DC is read-only, before anything is asked or saved (2.1.6.52, revised
             2026-10-13): such a change cannot be sent to another DC, and saved here it would never take effect.
    Inputs:  v — fabric vars (ad_dc_type), or None (nothing known: allowed); what — the change, starting the refusal
             ("Group Policy is", "who may sign in is").
    Returns: None.
    Fails:   ValidationError at a read-only DC's site, saying to make the change at the site above.
    Feeds:   samba/gpo_request, samba/set_logon_policy, samba/clear_logon_policy."""
    if (v or {}).get("ad_dc_type") == "rodc":
        raise ValidationError(f"this site's domain controller is read-only, and {what} kept on a writable domain "
                              "controller's own copy: make the change at the site above (its GPOs reach this site); "
                              "nothing was changed")
