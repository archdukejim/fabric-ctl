from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options


def _fields(v, level, value, enforced, site):
    """Purpose: a scan policy change's level, key and fields, checked (manual 1.10.4.27.5).
    Inputs:  v — fabric vars (site_name); level — "org" or "site"; value — as typed; enforced — None (keep) or bool;
             site — the site ("" this one).
    Returns: (key: "org" or the site's name, fields: {"policy" ("allow", "deny" or "" for inherit), "enforced"?}).
    Fails:   ValidationError: a level other than org or site; a value the level does not take; --enforced on a site's
             level; --site with the organisation's.
    Feeds:   set_scan_policy."""
    level, value = str(level or "").strip().lower(), str(value or "").strip().lower()
    if level == "org":
        if value not in ("allow", "deny"):
            raise ValidationError(f"the organisation's scan policy is allow or deny (got {value!r})")
        if site:
            raise ValidationError("--site names a site's level: the organisation's level is one value for every site")
        return "org", {"policy": value, **({} if enforced is None else {"enforced": bool(enforced)})}
    if level == "site":
        if value not in ("allow", "deny", "inherit"):
            raise ValidationError(f"a site's scan policy is allow, deny or inherit (got {value!r})")
        if enforced is not None:
            raise ValidationError("--enforced is the organisation's: a site's level is never enforced over another")
        return (site or v["site_name"]), {"policy": "" if value == "inherit" else value}
    raise ValidationError(f"the scan policy's level is org or site (got {level!r})")


def set_scan_policy(v, actor, level, value, enforced=None, site="", secrets=None, container="samba", source="cli"):
    """Purpose: set one level of the scan policy (decision 2.1.10.28, manual 1.10.4.27.5): the organisation's (allow or
             deny, enforced or not: written where the organisation's DHCP options are, so AD lets the top site's agent
             and the sites in fabric-dhcp-org-editors write it) or a site's (allow, deny, or inherit: its own agent and
             any site above it). Written at a writable DC and audited (IPAM_SCAN_POLICY_SET) through
             common/edit_options; nothing is applied: the next scan reads it.
    Inputs:  v — fabric vars (site_name, ad_dc_type, ad_join_server); actor — who asks (audit); level — "org" or
             "site"; value — "allow", "deny" or (a site's) "inherit"; enforced — None to keep it, or bool (the
             organisation's only); site — a site's level: the site ("" this one); secrets, container — as read_plan;
             source — "cli" or "web".
    Returns: edit_options' result; its "result": {"level", "site" ("org" or the site), "policy" ("allow", "deny" or
             "inherit"), "enforced" (bool or None: the organisation's, kept when not given)}.
    Fails:   ValidationError: _fields' refusals; a site with no OU ("no such site"); the directory refusing ("not
             permitted for this site": the organisation's level from a site the top has not added, another site's level
             from a house; the organisation's entry not there yet); the DC not answering; a read-only DC with no
             writable partner.
    Feeds:   run_scan_policy_command (scan-policy set), agent POST /v1/ipam/scan-policy[/org]."""
    key, fields = _fields(v, level, value, enforced, site)

    def change(plan):
        before = (plan.get("scan_policy") or {}).get(key) or {}
        result = {"level": "org" if key == "org" else "site", "site": key, "policy": fields["policy"] or "inherit",
                  "enforced": fields.get("enforced", before.get("enforced")) if key == "org" else None}
        detail = (f"level={result['level']} site={key} policy={result['policy']}"
                  + (f" enforced={fields['enforced']}" if "enforced" in fields else ""))
        return ([{"do": "set", "what": "scan_policy", "site": v["site_name"] if key == "org" else key, "key": key,
                  "fields": fields}], result, detail, [])

    return edit_options(v, actor, "" if key == "org" else key, "IPAM_SCAN_POLICY_SET", change, secrets, container,
                        source)
