from webui.views.constants import SERVICES
from webui.views.render_page import render_page


def overview(ctx, services, host_changes=(), relaxed=(), certs=(), images=None, err="", wizard=None):
    """Purpose: The Overview tab: one tile per service with a traffic light and a link to its tab (only one
             its viewer may open); then
             the host changes fabric may make (approved, declined with what that leaves unmanaged).
    Inputs:  ctx — page context (src/webui/session/page_context); services — list of (name, systemd state, container
             health) from
             agentclient.service_status(); names are described via SERVICES;
             host_changes — agentclient.host_changes(): what fabric may change on the host, by group ([] for an
             install set up before fabric asked); relaxed — agentclient.relaxed_settings(): the security
             relaxations turned on (global Rule 10), shown at the top while any is; certs —
             agentclient.cert_warnings(): what is wrong or coming with the certificates (2.1.5.4), shown at the top;
             images — agentclient.image_rows() for the Updates section (None: unreadable); err — a refused job;
             wizard — the setup wizard's record ({"finished", ...}: Finish setting up shown until it is applied once or
             dismissed, manual 1.8.5.3; None: not shown, e.g. without settings:admin).
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/get_page (/); devserver; tests/webui/test_devserver.py.
    """
    return render_page("overview", ctx=ctx, tab="overview", services=services, service_info=SERVICES,
                       host_changes=list(host_changes), relaxed=list(relaxed),
                       certs=list(certs), images=images, err=err, wizard=wizard)
