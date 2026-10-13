import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.constants import SESSION_COOKIE
from webui.httpio.cookie_header import cookie_header
from webui.routes.directory_post import directory_post
from webui.routes.dns_filter_post import dns_filter_post
from webui.routes.kea_post import kea_post
from webui.routes.networks_scan_post import networks_scan_post
from webui.routes.overview_post import overview_post
from webui.routes.radius_post import radius_post
from webui.routes.saved_and_applied import saved_and_applied
from webui.routes.stepca_post import stepca_post
from webui.routes.tsig_post import tsig_post
from webui.routes.security_post import security_post
from webui.routes.vault_post import vault_post
from webui.routes.zone_post import zone_post
from webui.routes.zones_post import zones_post
from webui.session.page_context import page_context


def _segments(path, skip):
    """Purpose: The URL-decoded path segments after the first `skip` ones.
    Inputs:  path — str; skip — int.
    Returns: list of str.
    Fails:   never.
    Feeds:   post_action."""
    return [urllib.parse.unquote(p) for p in path.split("/")[skip:]]


def _radius_people(parts, form):
    """Purpose: Who may join by password: map a directory group (with an optional VLAN), or unmap it.
    Inputs:  parts — segments after /freeradius/people: [] (form group, vlan, priority) or [<group>, 'delete'].
    Returns: (agent result, message), or None for another path.
    Fails:   agent errors propagate (saved_and_applied handles ValidationError).
    Feeds:   post_action."""
    if not parts:
        res = actions.map_radius_group(form.get("group", ""), form.get("vlan", ""), form.get("priority", ""))
        m = res["mapping"]
        return res, f"Members of {m['group']} may join by password" + (f" on VLAN {m['vlan']}." if m["vlan"] else ".")
    if len(parts) == 2 and parts[1] == "delete":
        return actions.unmap_radius_group(parts[0]), f"Members of {parts[0]} may no longer join by password."
    return None


def post_action(h, sess, path, form):
    """Purpose: Route a signed-in, CSRF-checked POST to its action.
    Inputs:  h — the request handler (app, send, redirect, deny); sess — dict from find_session; path — str; form —
             dict from read_form. Routes: /logout; /bind9/zone/…; /bind9/zones/…; /apply; /stepca/…; /openbao/…;
             /directory/…; /kea/… (reservations, subnets, options, classes); /networks/scan[/record]; /dns-filter/…
             (lists, rules, upstreams, fetch); /overview/… (jobs); /freeradius/clients…;
             /freeradius/people…; /bind9/tsig/….
    Returns: /logout: session dropped, LOGOUT audited, 303 to Keycloak's logout URL clearing the session cookie;
             /apply: 200 apply result; the rest as their route modules.
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
    if path == "/apply":
        ok, output = actions.apply_changes(user)
        return h.send(200, views.apply_result(page_context(sess), ok, output))
    if path.startswith("/overview/"):
        return overview_post(h, _segments(path, 2))
    if path.startswith("/stepca/"):
        return stepca_post(h, sess, path[len("/stepca/"):], form)
    if path.startswith("/openbao/"):
        return vault_post(h, sess, _segments(path, 2), form)
    if path.startswith("/security/"):
        return security_post(h, sess, _segments(path, 2), form)
    if path.startswith("/directory/"):
        return directory_post(h, sess, _segments(path, 2), form)
    if path.startswith("/kea/"):
        return kea_post(h, _segments(path, 2), form)
    if path == "/networks/scan" or path.startswith("/networks/scan/"):
        return networks_scan_post(h, sess, _segments(path, 3), form)
    if path.startswith("/dns-filter/"):
        return dns_filter_post(h, _segments(path, 2), form)
    if path.startswith("/freeradius/clients"):
        return radius_post(h, sess, _segments(path, 3), form)
    if path.startswith("/freeradius/people"):
        return saved_and_applied(h, "/freeradius", lambda: _radius_people(_segments(path, 3), form))
    if path.startswith("/bind9/tsig/"):
        return tsig_post(h, sess, urllib.parse.unquote(path[len("/bind9/tsig/"):]), form)
    return h.deny(404, "Not found.")
