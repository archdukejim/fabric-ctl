from webui import agentclient as actions
from webui import views


def bind9_page(h, ctx, query, status=200):
    """Purpose: Render the BIND9 tab: forward zone records, the landing page's links (manual 1.4.2.4), generated
             reverse zones, the names DHCP registered (read-only, from Kea's leases: manual 1.10.3.6) or TSIG keys.
    Inputs:  h — the request handler (send, deny); ctx — page context; query — dict: view ('landing', 'reverse',
             'dhcp', 'tsig', 'new' (Add zone) or 'key' (one TSIG key's page, with key: its name); anything else is
             forward), zone (a zone key; default the first forward zone; the landing section always shows the site's
             zone); status — int, default 200.
    Returns: the BIND9 page with the given status; 404 for a TSIG key that is not there (2.1.8.16).
    Fails:   agent errors propagate to handle_request (400, redirect to /login, 403, 503) (e.g. an unknown zone key →
             400).
    Feeds:   get_page (/dns/zones) and tsig_post (re-shows the TSIG section with 400 on a validation error).
    """
    section = (query.get("view") if query.get("view") in ("landing", "reverse", "dhcp", "tsig", "new", "key")
               else "forward")
    zones = actions.list_zones()
    forward = [z for z in zones if not z.get("reverse")]
    key = query.get("zone") or (forward[0]["key"] if forward else "")
    if section == "landing":                     # the landing page links the site's own zone (1.4.2.2)
        key = "dynamic_zone_var"
    tsig = actions.list_tsig_keys() if section in ("tsig", "key") else None
    tsig_key = None
    if section == "key":                         # one TSIG key's page: by its name
        tsig_key = next((k for k in tsig if k.get("name") == query.get("key")), None)
        if tsig_key is None:
            return h.deny(404, "No TSIG key has that name.")
    return h.send(status, views.bind9(
        ctx, section, zones, zone=actions.zone_detail(key) if section in ("forward", "landing") and key else None,
        types=actions.RECORD_TYPES,
        tsig_keys=tsig, tsig_key=tsig_key,
        reverse=actions.reverse_zones() if section == "reverse" else None,
        dhcp=actions.dhcp_overview() if section == "dhcp" else None))
