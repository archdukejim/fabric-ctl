import time
import urllib.parse

from webui import agentclient as actions
from webui.constants import STEP_UP


def federation_post(h, sess, parts, form):
    """Purpose: the Federation page's changes: a site's read-only DC is lost or stolen (decision 2.1.6.58, manual
             4.9.1.3) — every account it held reset and the DC removed, one fabric-agent call after a recent sign-in
             and the site's name typed as confirmation (the agent allows it to the admin bundle only, and fabriclib
             only at a site above the lost DC's).
    Inputs:  h — the request handler (redirect, deny); sess — dict from find_session (user, auth_at); parts — path
             segments after /federation/: ['rodc-lost', <site>]; form — confirm (the site's name).
    Returns: 303 to /login?next=/federation… when the last sign-in is older than STEP_UP (300 s); otherwise 303 to
             /federation with msg (done) or, with the list again, err.
    Fails:   404 for any other path; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/federation/…).
    Notes:   The step-up is checked before the path, as for the vault's and the SSH page's changes."""
    if time.time() - sess.get("auth_at", 0) > STEP_UP:
        return h.redirect("/login?" + urllib.parse.urlencode({"next": "/federation?msg=" + urllib.parse.quote(
            "Signed in again. Repeat the step: handling a lost read-only DC needs a sign-in from the last 5 "
            "minutes.")}))
    if len(parts) != 2 or parts[0] != "rodc-lost" or not parts[1]:
        return h.deny(404, "Not found.")
    site = parts[1]
    try:
        res = actions.rodc_lost(site, form.get("confirm", ""))
    except actions.ValidationError as exc:
        return h.redirect("/federation?" + urllib.parse.urlencode({"rodc_lost": site, "err": str(exc)}))
    msg = (f"Site {site}: {len(res['reset'])} account(s) reset; read-only DC(s) removed: "
           f"{', '.join(res['removed']) or 'none left'}. Site {site} has no DC until a new one joins."
           if res["changed"] else " ".join(res["plan"]["lines"]))
    return h.redirect("/federation?" + urllib.parse.urlencode({"msg": msg}))
