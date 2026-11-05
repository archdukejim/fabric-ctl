import copy

from fabriclib.common.errors import ValidationError
from fabriclib.dns.common.own_names import own_names

OWN_KEY = "dns_fabric_own"           # vars.yaml: the site zone's records the last render added as fabric's own


def _key(rtype, record):
    """Purpose: a record as comparable data.
    Inputs:  rtype — "A" or "CNAME"; record — the record dict (name, ip or canonical).
    Returns: (rtype, name, value without a trailing dot).
    Fails:   never.
    Feeds:   _previous, drop_previous_own."""
    value = record.get("canonical") if rtype == "CNAME" else record.get("ip")
    return rtype, str(record.get("name") or ""), str(value or "").rstrip(".")


def _previous(v, zone):
    """Purpose: the records the previous render added as fabric's own: the list it kept, or, for an install from
             before 0.9.2 that kept none, only the zone's records that match fabric's names under today's settings
             exactly (positive evidence: nothing else is taken for fabric's).
    Inputs:  v — the settings; zone — the site zone's records (dns.dynamic_zone_var).
    Returns: set of (type, name, value).
    Fails:   ValidationError when dns_fabric_own is there but is not fabric's list.
    Feeds:   drop_previous_own."""
    kept = v.get(OWN_KEY)
    if kept is None:
        # the console's name as vars.yaml.j2 makes it, for settings that are not a render's yet (a settings file)
        mgr = v.get("hostname_mgr") or (v.get("webui_hostname") or f"{v.get('cname_mgr') or 'fabric-ctl'}."
                                                                   f"{v.get('domain') or ''}")
        names = own_names({**v, "hostname_mgr": str(mgr).lower()})
        return {_key(t, r) for t in ("A", "CNAME") for r in zone.get(t) or [] if isinstance(r, dict)
                and (t, str(r.get("name") or "")) in names
                and _key(t, r)[2] == names[(t, str(r.get("name") or ""))][0]}
    if not isinstance(kept, dict) or set(kept) - {"A", "CNAME"} or \
            not all(isinstance(kept.get(t) or [], list) and all(isinstance(r, dict) for r in kept.get(t) or [])
                    for t in ("A", "CNAME")):
        raise ValidationError(f"{OWN_KEY} {kept!r} is not fabric's list of its own records (A and CNAME lists): it is "
                              "fabric's own record of what the last apply added to the site's zone (manual 1.4.1.9); "
                              "leave it out of a settings file")
    return {_key(t, r) for t in ("A", "CNAME") for r in kept.get(t) or []}


def drop_previous_own(custom_vars):
    """Purpose: the site's zone without the names the previous render added as fabric's own, so a render after a move
             or a rename adds them at the new address and under the new name only (decision 2.1.1.74, known issue
             2.3.1.34): before 0.9.2 each render merged its names with the previous render's copies, which vars.yaml
             keeps, so the old address and name stayed in the zone. An admin's alias of the host's old name follows
             it to the new one; the landing page's alias is the admin's record (2.1.4.6) and is never dropped.
    Inputs:  custom_vars — the admin's vars (vars.yaml as installed); reads dns.dynamic_zone_var, dns_fabric_own (the
             list templates/vars.yaml.j2 writes), hostname, domain, landing_page_cname, and own_names' settings.
    Returns: a deep copy of custom_vars with the site zone's A and CNAME lists so cleaned (custom_vars as it is when
             there is no site zone).
    Fails:   ValidationError when dns_fabric_own is there but is not a mapping of A and CNAME lists of records.
    Feeds:   deploy/render_vars (before vars.yaml.j2 renders)."""
    v = copy.deepcopy(custom_vars)
    dns = v.get("dns")
    zone = dns.get("dynamic_zone_var") if isinstance(dns, dict) else None
    if not isinstance(zone, dict):
        if v.get(OWN_KEY) is not None:
            _previous(v, {})                         # a bad list is refused even with no zone to clean
        return v
    previous = _previous(v, zone)
    landing = str(v.get("landing_page_cname") or "info")
    # the render adds the landing alias until the install has once been ready (vars.yaml.j2, 2.1.4.10): until then
    # it is dropped with fabric's own, so it keeps its place; from then on it is the admin's and stays
    adds_landing = "hostname_landing" not in v or not v.get("install_was_ready", True)
    old_hosts = {name for t, name, _ in previous if t == "A" and name != "@"}
    host, domain = str(v.get("hostname") or ""), str(v.get("domain") or "")
    for t in ("A", "CNAME"):
        if not isinstance(zone.get(t), list):
            continue
        kept = []
        for r in zone[t]:
            if not isinstance(r, dict):
                kept.append(r)
                continue
            is_landing = t == "CNAME" and str(r.get("name") or "") == landing
            if (_key(t, r) in previous and not is_landing) or \
                    (is_landing and adds_landing and _key(t, r)[2] in (host, *old_hosts)):
                continue                              # fabric's own: the render adds it again from today's settings
            target = str(r.get("canonical") or "").rstrip(".") if t == "CNAME" else ""
            if host and target and target not in (host, f"{host}.{domain}") and \
                    any(target in (old, f"{old}.{domain}") for old in old_hosts):
                r = {**r, "canonical": host}          # an alias of the host's old name follows the rename
            kept.append(r)
        zone[t] = kept
    return v
