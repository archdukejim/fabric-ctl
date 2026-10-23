import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.routes.bind9_page import bind9_page
from webui.routes.directory_page import directory_page
from webui.routes.finish_setting_up import finish_setting_up
from webui.routes.dns_filter_page import dns_filter_page
from webui.routes.moved_to import moved_to
from webui.routes.openbao_page import openbao_page
from webui.routes.settings_page import settings_page
from webui.routes.stepca_page import stepca_page
from webui.session.page_context import page_context

SIGNED_IN = "Signed in again. Repeat the change: it needs a sign-in from the last 5 minutes."


def _overview(h, sess, ctx, path):
    """Purpose: The Overview entry's pages: Health (/), Doctor, Updates.
    Inputs:  h — the request handler; sess — the session; ctx — page context; path — "/", "/overview/doctor" or
             "/overview/updates".
    Returns: the page sent (Health: the host changes fabric may make, the host's reminders read afresh and, until the
             setup wizard is finished, Finish setting up — its first view in a sign-in opens the wizard instead, 303
             to /settings).
    Fails:   agent errors propagate to handle_request.
    Feeds:   get_page."""
    if path == "/overview/doctor":
        return h.send(200, views.overview(ctx, page=path))
    if path == "/overview/updates":
        try:
            images = actions.image_rows()
        except (actions.AgentError, actions.ValidationError):
            images = None
        return h.send(200, views.overview(ctx, images=images, page=path))
    wizard, open_now = finish_setting_up(h, sess, ctx)
    if open_now:                                   # the first Overview of a sign-in opens the wizard (1.8.5.3)
        return h.redirect("/settings")
    try:                                           # Overview reads the reminders afresh (2.1.6.69)
        ctx["reminders"] = actions.host_reminders()
        with h.app.lock:                           # the session's other pages follow
            if sess.get("sid") in h.app.sessions:
                h.app.sessions[sess["sid"]]["reminders"] = ctx["reminders"]
    except (actions.AgentError, actions.ValidationError, actions.PermissionDenied):
        pass
    return h.send(200, views.overview(ctx, actions.service_status(), actions.host_changes(),
                                      actions.relaxed_settings(), actions.cert_warnings(), None, "", wizard))


def _rest(path, prefix):
    """Purpose: The one URL-decoded segment after a prefix (/8021x/devices/<name>), or None.
    Inputs:  path — str; prefix — str ending in "/".
    Returns: str or None (no segment, or more than one).
    Fails:   never.
    Feeds:   get_page."""
    rest = path[len(prefix):] if path.startswith(prefix) else ""
    return urllib.parse.unquote(rest) if rest and "/" not in rest else None


def get_page(h, sess, path, query):
    """Purpose: Route a signed-in GET to its page (the navigation of manual 1.8.6.4); an old address answers with a
             redirect to its new one (moved_to).
    Inputs:  h — the request handler (send, redirect, deny); sess — dict from find_session; path — str; query — dict
             (view, zone, device, name, slot, step, the query log's search as each page uses them).
    Returns: 303 to the new address of a page that moved; 200 page: Overview (/, /overview/doctor,
             /overview/updates, /audit), DNS (/dns/zones, /dns-filter), DHCP (/kea), PKI (/pki, /pki/acme),
             Directory (/directory/people|domain|machines|gpo), 802.1X (/8021x, /8021x/decisions, /8021x/guides,
             /8021x/devices[/<name>], /8021x/roles[/<name>]), Secrets (/secrets[/<view>]), Federation (/federation),
             Settings (/settings, /settings/export, /settings/sign-in), a job (/jobs/<id>).
    Fails:   404 for any other path; agent errors propagate to handle_request (400, redirect to /login, 403, 503).
    Feeds:   handler.Handler.handle_request.
    """
    new = moved_to(path, query)
    if new:
        return h.redirect(new)
    ctx = page_context(sess)
    if query.get("signed_in") and not ctx.get("flash"):     # back from a step-up sign-in: a fixed text, not the query's
        ctx["flash"] = {"ok": SIGNED_IN}
    if path == "/" or path == "/overview/doctor" or path == "/overview/updates":
        return _overview(h, sess, ctx, path)
    if path == "/audit":
        return h.send(200, views.audit(ctx, actions.read_audit()))
    if path.startswith("/jobs/") and path.count("/") == 2:
        return h.send(200, views.job_page(ctx, actions.read_job(path[len("/jobs/"):])))
    if path == "/dns/zones":
        return bind9_page(h, ctx, query)
    if path == "/dns-filter":
        return dns_filter_page(h, ctx, query)
    if path == "/kea":
        return h.send(200, views.kea(ctx, actions.dhcp_overview()))
    if path == "/pki":
        view = query.get("view", "ca")
        return stepca_page(h, ctx, "ca" if view == "acme" else view, device=query.get("device", ""))
    if path == "/pki/acme":
        return stepca_page(h, ctx, "acme")
    if path == "/directory/people" or path == "/directory/domain" or path == "/directory/machines" or (
            path == "/directory/gpo"):
        return directory_page(h, ctx, {**query, "view": path.rsplit("/", 1)[1]})
    if path == "/8021x/devices":
        return directory_page(h, ctx, {"view": "devices"})
    if path == "/8021x/roles":
        return directory_page(h, ctx, {"view": "roles"})
    if _rest(path, "/8021x/devices/"):
        return directory_page(h, ctx, {"view": "device", "name": _rest(path, "/8021x/devices/")})
    if _rest(path, "/8021x/roles/"):
        return directory_page(h, ctx, {"view": "role", "name": _rest(path, "/8021x/roles/")})
    if path == "/8021x" or path == "/8021x/decisions" or path == "/8021x/guides":
        view = {"/8021x": "overview", "/8021x/decisions": "decisions"}.get(path)
        view = view or (query.get("view") if query.get("view") in ("switches", "windows") else "switches")
        guides = actions.radius_guides() if view in ("switches", "windows") else None
        return h.send(200, views.freeradius(ctx, actions.radius_overview(), view=view, guides=guides))
    if path == "/secrets":
        return openbao_page(h, ctx, {**query, "view": "status"})
    if _rest(path, "/secrets/") in views.OPENBAO_VIEWS:
        return openbao_page(h, ctx, {**query, "view": _rest(path, "/secrets/")})
    if path == "/federation":
        return h.send(200, views.federation(ctx, actions.federation_overview()))
    if path == "/settings" or path == "/settings/export":
        return settings_page(h, sess, ctx, path, query)
    if path == "/settings/sign-in":
        return h.send(200, views.security(ctx, actions.security_layers()))
    return h.deny(404, "Not found.")
