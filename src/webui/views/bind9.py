from webui.views.constants import BIND9_SECTIONS, TSIG_ANY_TYPES, TSIG_SCOPES
from webui.views.render_page import render_page


def bind9(ctx, section, zones, zone=None, types=(), msg="", err="", tsig_keys=None, reverse=None, dhcp=None,
          tsig_key=None, tsig_choices=None, tsig_mode=None, tsig_zone=None, edit="", split=""):
    """Purpose: The BIND9 tab: forward zone records, changed in their table, the landing page's links (manual 1.4.2.4),
             generated reverse zones, DHCP's names (read-only), or TSIG keys.
    Inputs:  ctx — page context; section — 'forward' | 'new' | 'landing' | 'reverse' | 'dhcp' | 'tsig' | 'key' |
             'newkey'; tsig_key
             — one key of list_tsig_keys() for 'key'; zones — list of zone
             dicts from list_zones() (those with 'reverse' set are hand-written reverse zones); zone — zone_detail()
             dict for the forward section (the site's zone for the landing section), or None; types — record types
             for the add form; msg, err — flash texts; tsig_keys — list from list_tsig_keys() for the tsig section;
             reverse — reverse_zones() dict {'zones': {name: [ptr]}, 'skipped': [...]}, default empty; dhcp —
             dhcp_overview() dict for the dhcp section (enabled, ddns_zone, leases, leases_error), or None;
             tsig_choices — tsig_choices() of the zone a key's names are picked from ('key', and 'newkey' in ACME
             mode with its zone), or None; tsig_mode — 'acme' | 'custom' | None for 'newkey'; tsig_zone — the zone
             ACME mode picks from, or None; edit — "<type>-<index>": the record whose row is open to change
             (2.1.4.15), or ""; split — the zone's tab (2.1.4.18): a split's index, "new" (Add a split), else All
             networks; one the zone has not is All networks.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/bind9_page; devserver.
    """
    splits = (zone or {}).get("splits") or []
    tab = ("new" if split == "new" and (zone or {}).get("splittable") else
           int(split) if str(split).isdigit() and int(split) < len(splits) else None)
    return render_page("bind9", ctx=ctx, tab=tab, page="/dns/zones", section=section, bind9_sections=BIND9_SECTIONS,
                   forward_zones=[z for z in zones if not z.get("reverse")],
                   manual_reverse=[z for z in zones if z.get("reverse")], zone=zone, types=types, msg=msg,
                   err=err, tsig_keys=tsig_keys, tsig_key=tsig_key, reverse=reverse or {"zones": {}, "skipped": []},
                   dhcp=dhcp, tsig_choices=tsig_choices, tsig_mode=tsig_mode, tsig_zone=tsig_zone, edit=edit,
                   tsig_scopes=TSIG_SCOPES, tsig_any_types=TSIG_ANY_TYPES)
