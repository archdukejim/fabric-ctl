from webui import agentclient as actions
from webui import views
from webui.routes.note_kept import note_kept


def stepca_page(h, ctx, view, status=200, serial="", source="", **extra):
    """Purpose: Render the Step-CA tab for one sub-view, with the CA summary, linkable devices and the issued list
             where needed.
    Inputs:  h — the request handler (send); ctx — page context; view — str, one of views.STEPCA_VIEWS (anything else
             → 'ca'); status — int, default 200; serial — the certificate's serial for "cert", the machine's key
             for "machine"; source — the Issued list's filter (a list_certs source, "" for all); extra — passed to
             views.stepca (review, inspected, err, device; cert and pem for a certificate named by serial or file,
             1.5.1.9.2).
    Returns: the Step-CA page with the given status; 404 for a certificate or machine that is not there (2.1.8.16).
    Fails:   a failing CA summary shows as unreadable and a failing device list as no devices (AgentError,
             ValidationError only); errors from list_certs on the 'issued' and 'cert' views and
             acme_overview on the 'acme' view propagate to handle_request.
    Feeds:   get_page (/pki, /pki/acme, /pki/issued/<serial>, /pki/acme/<key>) and stepca_post (review and inspect
             results, validation errors with 400).
    """
    if view not in views.STEPCA_VIEWS:
        view = "ca"
    try:
        ca = note_kept(ctx, actions.ca_summary(), "pki/ca", "/pki")
    except (actions.AgentError, actions.ValidationError):
        ca = None
    devices = []
    if view in ("sign", "issue"):
        try:                                # linking to a device is optional; the directory may be down
            devices = actions.device_overview()["devices"]
        except (actions.AgentError, actions.ValidationError):
            pass
    certs = actions.list_certs() if view == "issued" or (view == "cert" and not extra.get("cert")) else None
    issued = None
    if certs is not None:                   # every certificate the console can revoke (2.1.5.13), or one source
        issued = [c for c in certs.get("certs") or [] if not source or c.get("source") == source]
        extra.update(sources=certs.get("sources") or {}, source=source, stepca_error=certs.get("stepca_error", ""),
                     service_error=certs.get("service_error", ""),
                     counts={s: sum(1 for c in certs.get("certs") or [] if c.get("source") == s)
                             for s in certs.get("sources") or {}})
    acme = actions.acme_overview() if view in ("acme", "machine") else None
    if view == "cert" and not extra.get("cert"):          # one certificate's page: by its serial
        want = serial.replace(":", "").upper().lstrip("0")
        extra["cert"] = next((c for c in issued if c.get("serial") and c["serial"] == want), None)
        if extra["cert"] is None:
            return h.deny(404, "No certificate in Issued has that serial: give it to Revoke a certificate not listed.")
    if view == "machine":                   # one enrolled machine's page: by its key
        extra["machine"] = next((m for m in acme.get("machines") or [] if m.get("key") == serial), None)
        if extra["machine"] is None:
            return h.deny(404, "No machine is enrolled with that key.")
    return h.send(status, views.stepca(ctx, view, ca, issued=issued, devices=devices, acme=acme, **extra))
