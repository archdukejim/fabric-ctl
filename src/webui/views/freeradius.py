from webui.views.b64 import b64
from webui.views.constants import FREERADIUS_SECTIONS
from webui.views.render_page import render_page


def freeradius(ctx, overview, msg="", err="", view="overview", guides=None, sessions=None):
    """Purpose: The FreeRADIUS tab: overview (server, people groups, RADIUS clients with vendor and transport, recent
             decisions), the open sessions with Disconnect / Re-authenticate / Move VLAN where the vendor has CoA, or a
             setup guide for switches (per vendor) or Windows.
    Inputs:  ctx — page context; overview — radius_overview() dict (enabled, host_ip, server_name, people, clients,
             vendors, log, log_error); msg, err — flash texts; view — 'overview', 'sessions', 'switches' or 'windows'
             (anything else → overview); sessions — radius_sessions() dict for the sessions view (None: none);
             guides — radius_guides() dict for the guides; each guides['windows'][method]['script'] is
             base64-encoded here for its download link.
    Returns: HTML str.
    Fails:   KeyError if a Windows guide entry has no 'script'; other jinja2 errors propagate (e.g. UndefinedError
             when the template reads an attribute of a value the caller left out).
    Feeds:   src/webui/routes/get_page (/freeradius); devserver.
    """
    g = dict(guides or {})
    if g.get("windows"):
        g["windows"] = {m: dict(w, b64=b64(w["script"])) for m, w in g["windows"].items()}
    return render_page("freeradius", ctx=ctx, tab="freeradius", r=overview, msg=msg, err=err, g=g,
                       s=sessions or {"sessions": [], "error": ""},
                       view=view if view in dict(FREERADIUS_SECTIONS) else "overview", sections=FREERADIUS_SECTIONS)
