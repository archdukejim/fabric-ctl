import hmac
import secrets
import time

from webui import agentclient as actions
from webui import views
from webui.constants import LOGIN_COOKIE, SESSION_COOKIE
from webui.httpio.cookie_header import cookie_header
from webui.httpio.read_cookie import read_cookie
from webui.oidc import OIDCError
from webui.security.token_perms import token_perms


def finish_login(h, cert, query):
    """Purpose: Finish a Keycloak sign-in: check the attempt, verify the tokens, check the person against the
             certificate and their fabric roles, and create the session.
    Inputs:  h — the request handler (app, headers, send, deny); cert — dict from verified_client_cert (NO_CERT while
             the web console requires no certificate: the CN check is skipped); query — dict
             with state, code or error; reads the __Host-webui-login cookie and App.pending.
    Returns: 200 'Signed in' page (meta refresh to the stored next path) that sets __Host-webui (the session id,
             Max-Age session_max) and clears the login cookie; the session gets a new CSRF token, the tokens, perms,
             auth_at and, for a viewer with status:read, the host's reminders (host_reminders: shown in the top bar of
             every page until the next sign-in; [] when the agent cannot say); LOGIN is audited.
    Fails:   400 when the state is unknown or expired, the login cookie does not match, or another certificate started
             the login (the attempt is used up either way); 401 when Keycloak returned an error or no code; 401 'Login
             failed: …' on OIDCError; 403 when the Keycloak username is not the certificate CN, and 403 when the token
             has no fabric role (both audited as LOGIN_DENIED). Agent errors from the audit calls propagate to
             handle_request.
    Feeds:   handler.Handler.handle_request (GET /oidc/callback).
    Notes:   A 200 with meta refresh rather than a redirect, so the first request carrying the Strict session cookie
             starts from this origin. auth_at is the token's auth_time (never later than now), used by the vault
             step-up.
    """
    app = h.app
    state = query.get("state", "")
    with app.lock:
        pending = app.pending.pop(state, None)
    if (not pending or not hmac.compare_digest(read_cookie(h.headers, LOGIN_COOKIE) or "", state)
            or pending["fp"] != cert["fp"]):
        return h.deny(400, "Login expired or was started in another browser. Sign in again.")
    if "error" in query or "code" not in query:
        return h.deny(401, "Login was cancelled or refused by the identity provider.")
    try:
        claims, id_token, refresh_token = app.oidc.finish_login(query["code"], pending["verifier"], pending["nonce"])
    except OIDCError as exc:
        return h.deny(401, f"Login failed: {exc}")

    user = claims.get("preferred_username", "")
    actions.set_token(id_token)          # the audit calls below go to fabric-agent as this user
    if cert["cn"] is not None and user != cert["cn"]:          # gate 5, while a certificate is required
        actions.audit(user or "unknown", "LOGIN_DENIED", f"cert CN {cert['cn']!r} does not match user")
        return h.deny(403, "Your client certificate does not belong to this user.")
    perms = token_perms(claims)
    if not perms:
        actions.audit(user, "LOGIN_DENIED", "no fabric role")
        return h.deny(403, f"Your account has no fabric role (for example '{app.admin_role}'). "
                           "Ask an administrator to add you to a fabric group.")

    sid = secrets.token_urlsafe(32)
    now = time.time()
    with app.lock:
        app.sessions[sid] = {"user": user, "fp": cert["fp"], "csrf": secrets.token_urlsafe(32),
                             "id_token": id_token, "refresh_token": refresh_token, "perms": perms,
                             "exp": float(claims.get("exp") or now), "created": now, "last": now,
                             # when the person last signed in (step-up for vault changes and raising security)
                             "auth_at": min(float(claims.get("auth_time") or now), now)}
    actions.audit(user, "LOGIN", f"cert={cert['fp'][:16]}" if cert["fp"] else "no client certificate")
    if "status:read" in perms:               # the host's reminders, at each sign-in, on every page (2.1.6.69)
        try:
            reminders = actions.host_reminders()
        except (actions.AgentError, actions.ValidationError, actions.PermissionDenied):
            reminders = []
        with app.lock:
            app.sessions[sid]["reminders"] = reminders
    h.send(200, views.continue_page(pending.get("next") or "/"), headers=[
        cookie_header(SESSION_COOKIE, sid, app.max_age), cookie_header(LOGIN_COOKIE, "", 0, "Lax")])
