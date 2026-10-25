import urllib.parse

from webui import agentclient as actions
from webui.constants import SESSION_COOKIE
from webui.httpio.cookie_header import cookie_header
from webui.routes.account_post import account_post
from webui.routes.changes_post import changes_post
from webui.routes.directory_post import directory_post
from webui.routes.dns_filter_post import dns_filter_post
from webui.routes.kea_post import kea_post
from webui.routes.landing_post import landing_post
from webui.routes.overview_post import overview_post
from webui.routes.held import held, q
from webui.routes.radius_post import radius_post
from webui.routes.stepca_post import stepca_post
from webui.routes.tsig_post import tsig_post
from webui.routes.security_post import security_post
from webui.routes.settings_post import settings_post
from webui.routes.vault_post import vault_post
from webui.routes.zone_post import zone_post
from webui.routes.zones_post import zones_post


def _segments(path, skip):
    """Purpose: The URL-decoded path segments after the first `skip` ones.
    Inputs:  path — str; skip — int.
    Returns: list of str.
    Fails:   never.
    Feeds:   post_action."""
    return [urllib.parse.unquote(p) for p in path.split("/")[skip:]]


def _radius_people(h, parts, form):
    """Purpose: Who may join by password: map a directory group (with an optional VLAN), or unmap it; each held for
             the RADIUS clients page's Apply (1.8.6.5).
    Inputs:  h — the request handler; parts — segments after /freeradius/people: [] (form group, vlan, priority) or
             [<group>, 'delete'].
    Returns: 303 to /8021x saying the change waits for Apply, or why not; 404 for another path.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   post_action."""
    if not parts:
        return held(h, "/8021x", "radius/people", {k: form.get(k, "").strip() for k in ("group", "vlan", "priority")})
    if len(parts) == 2 and parts[1] == "delete":
        return held(h, "/8021x", f"radius/people/{q(parts[0])}/delete", {})
    return h.deny(404, "Not found.")


def post_action(h, sess, path, form):
    """Purpose: Route a signed-in, CSRF-checked POST to its action.
    Inputs:  h — the request handler (app, send, redirect, deny); sess — dict from find_session; path — str; form —
             dict from read_form. Routes: /logout; /bind9/zone/…; /bind9/zones/…; /bind9/landing/…;
             /stepca/…; /openbao/…; /directory/…; /changes/<page>/apply|discard|drop (1.8.6.5); /account/password and
             /account/groups/<name>/members (1.8.6.6); /kea/…
             (reservations, subnets, options, classes); /dns-filter/…
             (lists, rules, upstreams, fetch); /overview/… (jobs); /freeradius/clients…; /freeradius/people…;
             /bind9/tsig/…; /settings/… (the setup wizard: step, plan, import, apply, dismiss).
    Returns: /logout: session dropped, LOGOUT audited, 303 to Keycloak's logout URL clearing the session cookie;
             the rest as their route modules.
    Fails:   404 for an unknown path; agent errors propagate to handle_request (400, redirect to /login, 403, 503).
    Feeds:   handler.Handler.handle_request.
    """
    user = sess["user"]
    if path == "/logout":
        with h.app.lock:
            h.app.sessions.pop(sess["sid"], None)
        actions.audit(user, "LOGOUT", "")
        return h.redirect(h.app.oidc.logout_url(sess["id_token"], h.app.public_url + "/"),
                          [cookie_header(SESSION_COOKIE, "", 0)])
    if path.startswith("/bind9/zone/"):
        return zone_post(h, user, path, form)
    if path.startswith("/bind9/zones/"):
        return zones_post(h, user, _segments(path, 3), form)
    if path.startswith("/bind9/landing/"):
        return landing_post(h, user, _segments(path, 3), form)
    if path.startswith("/overview/"):
        return overview_post(h, _segments(path, 2))
    if path.startswith("/stepca/"):
        return stepca_post(h, sess, path[len("/stepca/"):], form)
    if path.startswith("/openbao/"):
        return vault_post(h, sess, _segments(path, 2), form)
    if path.startswith("/security/"):
        return security_post(h, sess, _segments(path, 2), form)
    if path.startswith("/settings/"):
        return settings_post(h, sess, _segments(path, 2), form)
    if path.startswith("/directory/"):
        return directory_post(h, sess, _segments(path, 2), form)
    if path.startswith("/changes/"):                     # Apply per page (1.8.6.5)
        return changes_post(h, _segments(path, 2), form)
    if path.startswith("/account/"):                     # My account (1.8.6.6): the password, Groups I manage
        return account_post(h, _segments(path, 2), form)
    if path.startswith("/kea/"):
        return kea_post(h, _segments(path, 2), form)
    if path.startswith("/dns-filter/"):
        return dns_filter_post(h, _segments(path, 2), form)
    if path.startswith("/freeradius/clients"):
        return radius_post(h, sess, _segments(path, 3), form)
    if path.startswith("/freeradius/people"):
        return _radius_people(h, _segments(path, 3), form)
    if path.startswith("/bind9/tsig/"):
        return tsig_post(h, sess, urllib.parse.unquote(path[len("/bind9/tsig/"):]), form)
    return h.deny(404, "Not found.")
