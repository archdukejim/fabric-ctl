from webui.views.constants import KEY_TYPES, REVOKE_REASONS, STEPCA_MENU
from webui.views.render_page import render_page


def stepca(ctx, view, ca, issued=None, review=None, inspected=None, err="", devices=None, device="", msg="",
           acme=None, cert=None, machine=None, sources=None, source="", stepca_error="", counts=None, pem="",
           service_error=""):
    """Purpose: The Step-CA tab: CA details, sign a CSR, new key + certificate, inspect, convert, the issued list, or
             ACME for LAN machines.
    Inputs:  ctx — page context; view — one of STEPCA_VIEWS; ca — ca_summary() dict or None when unreadable; issued —
             list_issued() for the issued view; review — describe_csr() result to confirm before signing; inspected —
             inspect_pem() result; err — error text; devices — directory devices a certificate can be linked to (sign
             / issue); device — preselected device name; msg — what was done (a revocation); acme — acme_overview()
             for the acme view; cert — one issued certificate's row for the cert view (its page, /pki/issued/<serial>);
             machine — one enrolled machine for the machine view (/pki/acme/<key>); sources — {source: label} of the
             Issued list's filter, source — the one shown ("" all), counts — {source: rows}, service_error — why
             fabric's own could not be found, stepca_error — why Step-CA's database could not be read (2.1.5.13);
             pem — the certificate a revocation names by file (1.5.1.9.2), sent again with the confirmation.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/stepca_page; devserver.
    """
    return render_page("stepca", ctx=ctx, page="/pki/acme" if view in ("acme", "machine") else "/pki", view=view,
                       menu=STEPCA_MENU, ca=ca, issued=issued, review=review, inspected=inspected, err=err,
                       key_types=KEY_TYPES, devices=devices or [], device=device, msg=msg, acme=acme, cert=cert,
                       machine=machine, reasons=REVOKE_REASONS, sources=sources or {}, source=source,
                       stepca_error=stepca_error, counts=counts or {}, pem=pem,
                       service_error=service_error)
