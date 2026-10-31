from webui import agentclient as actions
from webui import views


def stepca_page(h, ctx, view, status=200, serial="", **extra):
    """Purpose: Render the Step-CA tab for one sub-view, with the CA summary, linkable devices and the issued list
             where needed.
    Inputs:  h — the request handler (send); ctx — page context; view — str, one of views.STEPCA_VIEWS (anything else
             → 'ca'); status — int, default 200; serial — the certificate's serial for "cert", the machine's key
             for "machine"; extra — passed to views.stepca (review, inspected, err, device).
    Returns: the Step-CA page with the given status; 404 for a certificate or machine that is not there (2.1.8.16).
    Fails:   a failing CA summary shows as unreadable and a failing device list as no devices (AgentError,
             ValidationError only); errors from list_issued on the 'issued' view and
             acme_overview on the 'acme' view propagate to handle_request.
    Feeds:   get_page (/pki, /pki/acme, /pki/issued/<serial>, /pki/acme/<key>) and stepca_post (review and inspect
             results, validation errors with 400).
    """
    if view not in views.STEPCA_VIEWS:
        view = "ca"
    try:
        ca = actions.ca_summary()
    except (actions.AgentError, actions.ValidationError):
        ca = None
    devices = []
    if view in ("sign", "issue"):
        try:                                # linking to a device is optional; the directory may be down
            devices = actions.device_overview()["devices"]
        except (actions.AgentError, actions.ValidationError):
            pass
    issued = actions.list_issued() if view in ("issued", "cert") else None
    acme = actions.acme_overview() if view in ("acme", "machine") else None
    if view == "cert":                      # one certificate's page: by its serial
        extra["cert"] = next((c for c in issued if c.get("serial") and c["serial"] == serial), None)
        if extra["cert"] is None:
            return h.deny(404, "No certificate issued by hand has that serial.")
    if view == "machine":                   # one enrolled machine's page: by its key
        extra["machine"] = next((m for m in acme.get("machines") or [] if m.get("key") == serial), None)
        if extra["machine"] is None:
            return h.deny(404, "No machine is enrolled with that key.")
    return h.send(status, views.stepca(ctx, view, ca, issued=issued, devices=devices, acme=acme, **extra))
