import re
import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.httpio.upload_value import upload_value
from webui.routes.held import held
from webui.routes.stepca_page import stepca_page
from webui.session.page_context import page_context


LIFETIME_FIELDS = ("service_days", "renew_after_days", "acme_days", "issue_default_days", "issue_max_days")


def stepca_post(h, sess, op, form):
    """Purpose: Manual PKI: each Step-CA form maps to one fabric-agent operation.
    Inputs:  h — the request handler (send, deny); sess — dict from find_session; op — str after /stepca/:
             'sign/review' (csr_file or csr, device), 'sign' (csr, days, device), 'issue' (cn, sans split on
             spaces/commas, key_type, days, device), 'inspect' (file or data), 'convert' (cert_file or cert, key_file or
             key), 'revoke/review' (serial, or cert_file or cert: Revoke a certificate not listed, 1.5.1.9.2), 'revoke'
             (target: the serial, or pem: the certificate; reason; confirm: the name typed again, 1.5.1.9.3),
             'lifetimes' (PKI → Lifetimes' fields and was_<field>, the values shown, 2.1.5.14), 'acme/enroll' (host,
             domain: a DNS-01 key for one machine); form — dict from read_form.
    Returns: sign/review: Step-CA sign view with the decoded request; inspect: inspect view with the result;
             revoke/review: the certificate's confirmation (its page), or Issued with the refusal (400);
             revoke: done at once (2.1.8.23), 303 back to the certificate's page with what was revoked (and the
             services that took a new certificate first), or to it with the refusal (to Issued for a certificate not
             listed there; the confirmation again, 400, for one given as a file); lifetimes: the values changed
             held for PKI's Apply (303 to Lifetimes, saying so or why not; none changed: said, nothing held);
             acme/enroll: the TSIG key page (its secret and rfc2136.ini, shown once; BIND takes it at once); sign,
             issue, convert: 200 result page with downloads (a private key only on this page, never stored).
    Fails:   404 for an unknown op; ValidationError → the form's view again with status 400 and the error; AgentError,
             PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/stepca/…).
    """
    ctx, user = page_context(sess), sess["user"]
    back = {"sign/review": "sign", "sign": "sign", "issue": "issue", "inspect": "inspect", "convert": "convert",
            "revoke": "issued", "revoke/review": "issued", "acme/enroll": "acme", "lifetimes": "lifetimes"}.get(op)
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
        if op == "lifetimes":                # held for PKI's Apply (2.1.5.14): the agent checks the limits now
            # only the values changed from those the page showed (was_<field>), so the change says what it changes
            fields = {k: form.get(k, "").strip() for k in LIFETIME_FIELDS
                      if form.get(k, "").strip() not in ("", form.get(f"was_{k}", "").strip())}
            if not fields:
                return h.back("/pki/lifetimes", msg="Nothing changed: the lifetimes are as shown.")
            return held(h, "/pki/lifetimes", "pki/lifetimes", {"fields": fields})
        if op == "revoke/review":            # Revoke a certificate not listed: by serial or file (1.5.1.9.2)
            pem = upload_value(form, "cert_file", "cert")
            row = actions.lookup_cert(user, form.get("serial", "").strip(), pem or "")
            return stepca_page(h, ctx, "cert", cert=row, pem=(pem or "") if row.get("source") == "file" else "")
        if op == "revoke":                   # at once, a listed exception to Apply per page (2.1.8.23)
            target, pem = form.get("target", ""), form.get("pem", "")
            back = "/pki/issued/" + urllib.parse.quote(target, safe="") if target and not pem else "/pki?view=issued"
            try:
                done = actions.revoke_cert(user, "" if pem else target, form.get("reason", "unspecified"), pem=pem,
                                           confirm=form.get("confirm", ""))
            except actions.ValidationError as exc:
                if pem:                      # its confirmation again, with the file it was given
                    row = actions.lookup_cert(user, "", pem)
                    return stepca_page(h, ctx, "cert", status=400, cert=row, pem=pem, err=str(exc))
                want = target.replace(":", "").upper().lstrip("0")
                if not any(c.get("serial") == want for c in actions.list_certs().get("certs") or []):
                    back = "/pki?view=issued"            # a certificate not listed: its page answers 404 (2.1.8.16)
                return h.back(back, err=str(exc))
            first = (f" A new certificate was issued first and is in use ({', '.join(sorted(done['replaced']))})."
                     if done.get("replaced") else "")
            return h.back(back, msg=f"Revoked {done['subject']} ({done['reason']}): refused from now on.{first}")
        result = actions.convert_cert(user, upload_value(form, "cert_file", "cert"),
                                      upload_value(form, "key_file", "key"))
        return h.send(200, views.pki_result(ctx, "convert", result))
    except actions.ValidationError as exc:
        if back == "lifetimes":
            return h.back("/pki/lifetimes", err=str(exc))
        return stepca_page(h, ctx, back, status=400, err=str(exc))
