from webui import agentclient as actions
from webui import views


def stepca_page(h, ctx, view, status=200, **extra):
    """Purpose: Render the Step-CA tab for one sub-view, with the CA summary, linkable devices, the issued list and the
             enrolments where needed.
    Inputs:  h — the request handler (send); ctx — page context; view — str, one of views.STEPCA_VIEWS (anything else
             → 'ca'); status — int, default 200; extra — passed to views.stepca (review, inspected, err, device).
    Returns: the Step-CA page with the given status.
    Fails:   a failing CA summary shows as unreadable and a failing device list as no devices (AgentError,
             ValidationError only); errors from list_issued on the 'issued' view and
             acme_overview on the 'acme' view and list_enrolments on the 'enrol' view propagate to handle_request.
    Feeds:   get_page (/stepca) and stepca_post (review and inspect results, validation errors with 400).
    """
    if view not in views.STEPCA_VIEWS:
        view = "ca"
    try:
        ca = actions.ca_summary()
    except (actions.AgentError, actions.ValidationError):
        ca = None
    devices = []
    if view in ("sign", "issue", "enrol"):
        try:                                # linking to a device is optional; the directory may be down
            devices = actions.device_overview()["devices"]
        except (actions.AgentError, actions.ValidationError):
            pass
    issued = actions.list_issued() if view == "issued" else None
    acme = actions.acme_overview() if view == "acme" else None
    enrolments = actions.list_enrolments() if view == "enrol" else None
    return h.send(status, views.stepca(ctx, view, ca, issued=issued, devices=devices, acme=acme,
                                       enrolments=enrolments, **extra))
