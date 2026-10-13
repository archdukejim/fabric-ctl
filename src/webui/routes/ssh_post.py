import time
import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.constants import STEP_UP
from webui.session.page_context import page_context


def ssh_post(h, sess, parts, form):
    """Purpose: the SSH page's changes (manual 1.6.11.9): sign a fabric admin's public key, or turn SSH certificates on
             or off — each one fabric-agent call after a recent sign-in, since each hands out or changes access.
    Inputs:  h — the request handler (send, redirect, deny); sess — dict from find_session (user, auth_at); parts —
             path segments after /ssh/: ['sign'] (public_key), ['on'] or ['off']; form — dict from read_form.
    Returns: 303 to /login?next=/ssh when the last sign-in is older than STEP_UP (300 s); sign: 200 the SSH page with
             the certificate, shown once with a download; on/off: 303 to /ssh with msg.
    Fails:   404 for any other path; ValidationError → sign: the SSH page with status 400 and the error, on/off: 303
             with err; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/ssh/…).
    Notes:   The step-up is checked before the path, as for the Security page's changes."""
    if time.time() - sess.get("auth_at", 0) > STEP_UP:
        return h.redirect("/login?" + urllib.parse.urlencode({"next": "/ssh?msg=" + urllib.parse.quote(
            "Signed in again. Repeat the step: SSH changes need a sign-in from the last 5 minutes.")}))
    if parts not in (["sign"], ["on"], ["off"]):
        return h.deny(404, "Not found.")
    ctx = page_context(sess)
    if parts == ["sign"]:
        try:
            signed = actions.sign_ssh_key(sess["user"], form.get("public_key", ""))
        except actions.ValidationError as exc:
            return h.send(400, views.ssh(ctx, actions.ssh_overview(), err=str(exc)))
        return h.send(200, views.ssh(ctx, actions.ssh_overview(), signed=signed))
    try:
        res = actions.set_ssh_certificates(sess["user"], parts == ["on"])
    except actions.ValidationError as exc:
        return h.redirect("/ssh?" + urllib.parse.urlencode({"err": str(exc)}))
    word = "on" if res["on"] else "off"
    msg = (f"SSH certificates are {word}." if res["changed"] else f"SSH certificates were {word} already.")
    if res["on"]:
        msg += " Joined machines trust the CA at their next fabric-managed run (within the hour)."
    return h.redirect("/ssh?" + urllib.parse.urlencode({"msg": msg}))
