from webui import agentclient as actions
from webui import views
from webui.routes.bind9_page import bind9_page
from webui.routes.directory_page import directory_page
from webui.routes.dns_filter_page import dns_filter_page
from webui.routes.openbao_page import openbao_page
from webui.routes.stepca_page import stepca_page
from webui.session.page_context import page_context


def get_page(h, sess, path, query):
    """Purpose: Route a signed-in GET to its page.
    Inputs:  h — the request handler (send, deny); sess — dict from find_session; path — str: /, /bind9, /stepca,
             /directory, /openbao, /kea, /dns-filter, /freeradius, /federation, /audit, /security, /ssh, /jobs/<id>;
             query — dict (view, zone, device, name, slot, msg, err, the query log's search as each page uses them).
    Returns: 200 page (overview with the host changes fabric may make, BIND9, Step-CA, directory, OpenBao, Kea,
             Federation, FreeRADIUS with its setup guides for view switches / windows, audit log, SSH
             certificates).
    Fails:   404 for any other path; agent errors propagate to handle_request (400, redirect to /login, 403, 503).
    Feeds:   handler.Handler.handle_request.
    """
    ctx = page_context(sess)
    if path == "/":
        try:
            images = actions.image_rows()
        except (actions.AgentError, actions.ValidationError):
            images = None
        return h.send(200, views.overview(ctx, actions.service_status(), actions.host_changes(),
                                             actions.relaxed_settings(), actions.cert_warnings(), images,
                                             query.get("err", "")))
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
    if path == "/kea":
        return h.send(200, views.kea(ctx, actions.dhcp_overview(), query.get("msg", ""), query.get("err", "")))
    if path == "/freeradius":
        view = query.get("view", "overview")
        guides = actions.radius_guides() if view in ("switches", "windows") else None
        return h.send(200, views.freeradius(ctx, actions.radius_overview(), query.get("msg", ""),
                                            query.get("err", ""), view, guides))
    if path == "/federation":
        return h.send(200, views.federation(ctx, actions.federation_overview()))
    if path == "/audit":
        return h.send(200, views.audit(ctx, actions.read_audit()))
    if path == "/ssh":
        return h.send(200, views.ssh(ctx, actions.ssh_overview(), msg=query.get("msg", ""), err=query.get("err", "")))
    if path == "/security":
        return h.send(200, views.security(ctx, actions.security_layers(), query.get("msg", ""), query.get("err", "")))
    return h.deny(404, "Not found.")
