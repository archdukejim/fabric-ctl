from webui.views.constants import BIND9_SECTIONS, TSIG_ANY_TYPES, TSIG_SCOPES
from webui.views.render_page import render_page


def bind9(ctx, section, zones, zone=None, types=(), msg="", err="", tsig_keys=None, reverse=None, dhcp=None):
    """Purpose: The BIND9 tab: forward zone records and the add form, the landing page's links (manual 1.4.2.4),
             generated reverse zones, DHCP's names (read-only), or TSIG keys.
    Inputs:  ctx — page context; section — 'forward' | 'landing' | 'reverse' | 'dhcp' | 'tsig'; zones — list of zone
             dicts from list_zones() (those with 'reverse' set are hand-written reverse zones); zone — zone_detail()
             dict for the forward section (the site's zone for the landing section), or None; types — record types
             for the add form; msg, err — flash texts; tsig_keys — list from list_tsig_keys() for the tsig section;
             reverse — reverse_zones() dict {'zones': {name: [ptr]}, 'skipped': [...]}, default empty; dhcp —
             dhcp_overview() dict for the dhcp section (enabled, ddns_zone, leases, leases_error), or None.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/bind9_page; devserver.
    """
    return render_page("bind9", ctx=ctx, tab="bind9", section=section, bind9_sections=BIND9_SECTIONS,
                   forward_zones=[z for z in zones if not z.get("reverse")],
                   manual_reverse=[z for z in zones if z.get("reverse")], zone=zone, types=types, msg=msg,
                   err=err, tsig_keys=tsig_keys, reverse=reverse or {"zones": {}, "skipped": []}, dhcp=dhcp,
                   tsig_scopes=TSIG_SCOPES, tsig_any_types=TSIG_ANY_TYPES)
