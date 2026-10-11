import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.check_filter_groups import YOUTUBE, check_filter_groups
from fabriclib.dns_filter.common.rule_names import NAME_RE, rule_names


def check_filter_settings(v):
    """Purpose: refuse DNS filter settings that cannot work (manual 1.12.2.7, 1.12.2.8, 1.12.2.15, 1.12.3), before
             anything is rendered; the rules and groups are normalised in place (lowercase, no trailing dot, no
             duplicates).
    Inputs:  v — rendered vars (dns_filter_lists, dns_filter_allow, dns_filter_block, dns_filter_upstreams,
             dns_filter_safe_search, dns_filter_youtube, dns_filter_groups, domain, org_domain, ad_domain, and what
             check_filter_groups reads); changed in place.
    Returns: None.
    Fails:   ValidationError naming the setting: a list without an http(s) url, the same url twice, enabled not true
             or false; an allow or block that is not a name, is inside fabric's domains, or is both allowed and
             blocked; no upstream, an upstream without an IP address or a certificate name; safe search not true or
             false, a YouTube level other than strict or moderate; what check_filter_groups refuses.
    Feeds:   deploy/check_settings (when dns_filter is bind); the console's changes (dns_filter/add_*, remove_*,
             set_*) before they save."""
    lists = v.get("dns_filter_lists") or []
    if not isinstance(lists, list):
        raise ValidationError("dns_filter_lists must be a list of {name, url}")
    seen = set()
    for item in lists:
        url = str((item or {}).get("url") or "").strip() if isinstance(item, dict) else ""
        if not url.startswith(("https://", "http://")):
            raise ValidationError(f"dns_filter_lists: {item!r} needs an http(s) url")
        if url in seen:
            raise ValidationError(f"dns_filter_lists: {url} is listed twice")
        if not isinstance(item.get("enabled", True), bool):
            raise ValidationError(f"dns_filter_lists: {url}: enabled is true or false")
        seen.add(url)
    own = [d for d in (v.get("domain"), v.get("org_domain"), v.get("ad_domain")) if d]
    v["dns_filter_allow"] = rule_names(v.get("dns_filter_allow"), "dns_filter_allow", own)
    v["dns_filter_block"] = rule_names(v.get("dns_filter_block"), "dns_filter_block", own)
    both = set(v["dns_filter_allow"]) & set(v["dns_filter_block"])
    if both:
        raise ValidationError(f"allowed and blocked at once: {', '.join(sorted(both))}")
    ups = v.get("dns_filter_upstreams") or []
    if not isinstance(ups, list) or not ups:
        raise ValidationError("dns_filter_upstreams must list at least one {address, name}: AdGuard Home forwards "
                              "to them (1.12.3.2)")
    for u in ups:
        try:
            ipaddress.ip_address(str((u or {}).get("address")))
        except ValueError:
            raise ValidationError(f"dns_filter_upstreams: {u!r} needs an IP address") from None
        if not NAME_RE.match(str(u.get("name") or "").lower()) or "." not in str(u.get("name")):
            raise ValidationError(f"dns_filter_upstreams: {u!r} needs the name its certificate is checked against")
    if not isinstance(v.get("dns_filter_safe_search", False), bool):
        raise ValidationError("dns_filter_safe_search is true or false")
    if str(v.get("dns_filter_youtube") or "strict") not in YOUTUBE:
        raise ValidationError(f"dns_filter_youtube is strict or moderate, not {v.get('dns_filter_youtube')!r}")
    check_filter_groups(v, own)
