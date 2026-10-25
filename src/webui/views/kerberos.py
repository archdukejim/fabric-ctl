from webui.views.constants import KERBEROS_FIELDS
from webui.views.render_page import render_page


def kerberos(ctx, overview=None, spns=None, unavailable="", spns_error=""):
    """Purpose: Directory · Kerberos (manual 1.6.12.9): sign-in with the domain logon (on or off, moved here from
             Security), the realm and its KDCs, the ticket policy (editable with domain:admin, on Kerberos' Apply), the
             service principals read-only with duplicates flagged.
    Inputs:  ctx — page context; overview — kerberos_overview's dict; spns — list_spns' dict; unavailable — why the
             overview could not be read; spns_error — why the SPNs could not be read.
    Returns: HTML str, in the navigation's Kerberos page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/kerberos_page; devserver."""
    return render_page("kerberos", ctx=ctx, page="/directory/kerberos", k=overview or {},
                       spns=spns or {"spns": [], "duplicates": []}, fields=KERBEROS_FIELDS,
                       unavailable=unavailable, spns_error=spns_error)
