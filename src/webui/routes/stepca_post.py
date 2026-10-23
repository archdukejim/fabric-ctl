import re
import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.httpio.upload_value import upload_value
from webui.routes.stepca_page import stepca_page
from webui.session.page_context import page_context


def stepca_post(h, sess, op, form):
    """Purpose: Manual PKI: each Step-CA form maps to one fabric-agent operation.
    Inputs:  h — the request handler (send, deny); sess — dict from find_session; op — str after /stepca/:
             'sign/review' (csr_file or csr, device), 'sign' (csr, days, device), 'issue' (cn, sans split on
             spaces/commas, key_type, days, device), 'inspect' (file or data), 'convert' (cert_file or cert, key_file or
             key), 'revoke' (target: the serial, reason), 'acme/enroll' (host, domain: a DNS-01 key for one machine);
             form — dict from read_form.
    Returns: sign/review: Step-CA sign view with the decoded request; inspect: inspect view with the result;
             revoke: done at once (2.1.8.23), 303 back to the certificate's page with what was revoked, or to it with
             the refusal (to the issued list for a certificate not listed there); acme/enroll: the TSIG key page
             (its secret and rfc2136.ini, shown once; BIND takes it at once); sign,
             issue, convert: 200 result page with downloads (a private key only on this page, never stored).
    Fails:   404 for an unknown op; ValidationError → the form's view again with status 400 and the error; AgentError,
             PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/stepca/…).
    """
    ctx, user = page_context(sess), sess["user"]
    back = {"sign/review": "sign", "sign": "sign", "issue": "issue", "inspect": "inspect", "convert": "convert",
            "revoke": "issued", "acme/enroll": "acme"}.get(op)
    if not back:
        return h.deny(404, "Not found.")
    try:
        if op == "acme/enroll":              # a DNS-01 key for one machine: fabric's TSIG key acme-<name> (2.1.5.8)
            host = form.get("host", "").strip().lower()
            r = actions.create_tsig_key(user, f"acme-{host}", form.get("domain", ""), "acme-hosts", [host], ["TXT"], "")
            return h.send(200, views.tsig_result(ctx, r["key"]["name"], r["secret"], r["ini"], "created",
                                                 r.get("publish_error", "")))
        if op == "sign/review":
            req = actions.describe_csr(user, upload_value(form, "csr_file", "csr"))
            return stepca_page(h, ctx, "sign", review=req, device=form.get("device", ""))
        if op == "sign":
            result = actions.sign_csr(user, form.get("csr", ""), form.get("days", ""), form.get("device", ""))
            return h.send(200, views.pki_result(ctx, "sign", result))
        if op == "issue":
            sans = [n for n in re.split(r"[\s,]+", form.get("sans", "")) if n]
            result = actions.issue_key_pair(user, form.get("cn", ""), sans, form.get("key_type", ""),
                                            form.get("days", ""), form.get("device", ""))
            return h.send(200, views.pki_result(ctx, "issue", result))
        if op == "inspect":
            return stepca_page(h, ctx, "inspect", inspected=actions.inspect_pem(user, upload_value(form, "file",
                                                                                                   "data")))
        if op == "revoke":                   # at once, a listed exception to Apply per page (2.1.8.23)
            target = form.get("target", "")
            back = "/pki/issued/" + urllib.parse.quote(target, safe="") if target else "/pki?view=issued"
            try:
                done = actions.revoke_cert(user, target, form.get("reason", "unspecified"))
            except actions.ValidationError as exc:     # a certificate not listed: its page answers 404 (2.1.8.16)
                if not any(c.get("serial") == target for c in actions.list_issued()):
                    back = "/pki?view=issued"
                return h.back(back, err=str(exc))
            return h.back(back, msg=f"Revoked {done['subject']} ({done['reason']}): refused from now on.")
        result = actions.convert_cert(user, upload_value(form, "cert_file", "cert"),
                                      upload_value(form, "key_file", "key"))
        return h.send(200, views.pki_result(ctx, "convert", result))
    except actions.ValidationError as exc:
        return stepca_page(h, ctx, back, status=400, err=str(exc))
