from webui import agentclient as actions
from webui import views
from webui.routes.bind9_page import bind9_page
from webui.routes.directory_page import directory_page
from webui.routes.finish_setting_up import finish_setting_up
from webui.routes.dns_filter_page import dns_filter_page
from webui.routes.networks_page import networks_page
from webui.routes.networks_scan_page import networks_scan_page
from webui.routes.openbao_page import openbao_page
from webui.routes.options_page import options_page
from webui.routes.settings_page import settings_page
from webui.routes.stepca_page import stepca_page
from webui.session.page_context import page_context


def get_page(h, sess, path, query):
    """Purpose: Route a signed-in GET to its page.
    Inputs:  h — the request handler (send, deny); sess — dict from find_session; path — str: /, /bind9, /stepca,
             /directory, /openbao, /kea, /kea/options, /networks, /networks/export, /networks/scan, /dns-filter,
             /freeradius, /federation, /audit, /security, /settings, /settings/export, /jobs/<id>; query — dict
             (view, zone, device, name, slot, site, subnet, q, target, step, msg, err, the query log's search as each
             page uses them).
    Returns: 200 page (overview with the host changes fabric may make and, until the setup wizard is finished, Finish
             setting up — its first view in a sign-in opens the wizard instead, 303 to /settings; BIND9, Step-CA,
             directory, OpenBao, Kea, Federation, FreeRADIUS with its setup guides for view switches / windows, audit
             log, the setup wizard and its settings file).
    Fails:   404 for any other path; agent errors propagate to handle_request (400, redirect to /login, 403, 503).
    Feeds:   handler.Handler.handle_request.
    """
    ctx = page_context(sess)
    if path == "/":
        wizard, open_now = finish_setting_up(h, sess, ctx)
        if open_now:                                   # the first Overview of a sign-in opens the wizard (1.8.5.3)
            return h.redirect("/settings")
        try:
            images = actions.image_rows()
        except (actions.AgentError, actions.ValidationError):
            images = None
        return h.send(200, views.overview(ctx, actions.service_status(), actions.host_changes(),
                                             actions.relaxed_settings(), actions.cert_warnings(), images,
                                             query.get("err", ""), wizard))
    if path.startswith("/jobs/") and path.count("/") == 2:
        return h.send(200, views.job_page(ctx, actions.read_job(path[len("/jobs/"):])))
    if path == "/bind9":
        return bind9_page(h, ctx, query)
    if path == "/stepca":
        return stepca_page(h, ctx, query.get("view", "ca"), device=query.get("device", ""))
    if path == "/directory":
        return directory_page(h, ctx, query)
    if path == "/openbao":
        return openbao_page(h, ctx, query)
    if path == "/dns-filter":
        return dns_filter_page(h, ctx, query)
    if path in ("/networks", "/networks/export"):
        return networks_page(h, ctx, path, query)
    if path == "/kea/options":
        return options_page(h, ctx, query)
    if path == "/kea":
        return h.send(200, views.kea(ctx, actions.dhcp_overview(), query.get("msg", ""), query.get("err", "")))
    if path == "/networks/scan":
        return networks_scan_page(h, ctx, query)
    if path == "/freeradius":
        view = query.get("view", "overview")
        guides = actions.radius_guides() if view in ("switches", "windows") else None
        return h.send(200, views.freeradius(ctx, actions.radius_overview(), query.get("msg", ""),
                                            query.get("err", ""), view, guides))
    if path == "/federation":
        return h.send(200, views.federation(ctx, actions.federation_overview()))
    if path == "/audit":
        return h.send(200, views.audit(ctx, actions.read_audit()))
    if path == "/settings":
        return settings_page(h, sess, ctx, path, query)
    if path == "/settings/export":
        return settings_page(h, sess, ctx, path, query)
    if path == "/security":
        return h.send(200, views.security(ctx, actions.security_layers(), query.get("msg", ""), query.get("err", "")))
    return h.deny(404, "Not found.")
