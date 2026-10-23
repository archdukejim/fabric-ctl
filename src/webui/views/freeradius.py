from webui.views.b64 import b64
from webui.views.constants import FREERADIUS_SECTIONS, RADIUS_PAGES
from webui.views.render_page import render_page


def freeradius(ctx, overview, msg="", err="", view="overview", guides=None):
    """Purpose: The 802.1X entry's pages: RADIUS clients (the server, the people groups, the RADIUS clients), Recent
             decisions, or a setup guide for switches or Windows.
    Inputs:  ctx — page context; overview — radius_overview() dict (enabled, host_ip, server_name, people, clients,
             log, log_error); msg, err — the page's message; view — 'overview', 'decisions', 'switches' or 'windows'
             (anything else → overview); guides — radius_guides() dict for the guides; each
             guides['windows'][method]['script'] is base64-encoded here for its download link.
    Returns: HTML str.
    Fails:   KeyError if a Windows guide entry has no 'script'; other jinja2 errors propagate (e.g. UndefinedError
             when the template reads an attribute of a value the caller left out).
    Feeds:   src/webui/routes/get_page (/8021x, /8021x/decisions, /8021x/guides); devserver.
    """
    g = dict(guides or {})
    if g.get("windows"):
        g["windows"] = {m: dict(w, b64=b64(w["script"])) for m, w in g["windows"].items()}
    view = view if view in RADIUS_PAGES else "overview"
    return render_page("freeradius", ctx=ctx, page=RADIUS_PAGES[view], r=overview, msg=msg, err=err, g=g,
                       view=view, sections=FREERADIUS_SECTIONS)
