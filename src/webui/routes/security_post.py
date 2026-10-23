import time

from webui import agentclient as actions
from webui.constants import STEP_UP
from webui.security.verified_client_cert import verified_client_cert

PAGE = "/settings/sign-in"
KERBEROS_PAGE = "/directory/kerberos"     # sign-in with the domain logon lives on Kerberos (manual 1.6.12.9)


def security_post(h, sess, parts, form):
    """Purpose: Settings → Sign-in security's changes (manual 2.3.6.2.6.4): raise a sign-in layer, or turn Kerberos
             sign-in on or off — each one fabric-agent call after a recent sign-in. Turning the client certificate on
             needs this browser to present the signed-in person's own certificate first, so the change never locks
             them out.
    Inputs:  h — the request handler (back, redirect, deny, headers, app); sess — dict from find_session (user,
             auth_at); parts — path segments after /security/: ['raise'] or ['kerberos']; form — layer, value.
    Returns: 303 to /login?next=<the page>?signed_in=1 when the last sign-in is older than STEP_UP (300 s);
             otherwise 303 to the page with what changed, or why not, as its message: /settings/sign-in for a layer,
             /directory/kerberos for Kerberos sign-in.
    Fails:   303 with the refusal on ValidationError (a lowering, an unknown layer or value) or a failed apply; 404 for
             any other path; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/security/…).
    Notes:   The step-up is checked before the path, as for the vault's changes."""
    page = KERBEROS_PAGE if parts == ["kerberos"] else PAGE
    if time.time() - sess.get("auth_at", 0) > STEP_UP:
        return h.redirect(f"/login?next={page}%3Fsigned_in%3D1")
    if parts not in (["raise"], ["kerberos"]):
        return h.deny(404, "Not found.")
    layer = "kerberos" if parts == ["kerberos"] else form.get("layer", "")
    value = form.get("value", "")
    if layer == "client-cert" and value == "on":
        mine = verified_client_cert(h.headers, h.app.issuer_dn)
        if not mine or mine["cn"] != sess["user"]:
            return h.back(PAGE, err=(
                "Your browser did not present your own client certificate. Import yours first (sudo fabricctl "
                f"client-cert {sess['user']}), open this page again, then turn the certificate on."))
    try:
        res = actions.raise_signin_layer(layer, value)
    except actions.ValidationError as exc:
        return h.back(page, err=str(exc))
    if not res.get("applied"):
        return h.back(page, err=f"{res['layer']} is saved as {res['to']} but did not apply: "
                                + (res.get("output") or "")[-300:])
    return h.back(page, msg=(f"{res['layer']}: {res['from']} → {res['to']}." if res["changed"]
                             else f"{res['layer']} was {res['to']} already."))
