from webui.views.b64 import b64
from webui.views.render_page import render_page


def pki_result(ctx, kind, r):
    """Purpose: The result page after signing, issuing or converting a certificate: details and every format as a
             download.
    Inputs:  ctx — page context; kind — 'sign' | 'issue' | 'convert'; r — the agent's result: name, cert, der_b64,
             fullchain, info (subject, sans, key, not_before, not_after, serial, sha256), and optionally p7b_b64,
             key, p12_b64, p12_password, device.
    Returns: HTML str with .crt, .cer, -fullchain.pem and, when present, .p7b, .key and .p12 downloads.
    Fails:   KeyError for another kind or when name, cert, der_b64 or fullchain is missing; other jinja2 errors
             propagate (e.g. UndefinedError when the template reads an attribute of a value the caller left out).
    Feeds:   src/webui/routes/stepca_post; devserver.
    Notes:   Files are data: links, so nothing (least of all a private key) is kept on the server for a later GET.
    """
    n = r["name"]
    files = [(f"{n}.crt", "application/x-x509-ca-cert", b64(r["cert"]), "certificate, PEM (Linux, most devices)"),
             (f"{n}.cer", "application/pkix-cert", r["der_b64"], "certificate, DER (Windows)"),
             (f"{n}-fullchain.pem", "application/x-pem-file", b64(r["fullchain"]),
              "certificate + CA chain, PEM (web servers)")]
    if r.get("p7b_b64"):
        files.append((f"{n}.p7b", "application/x-pkcs7-certificates", r["p7b_b64"], "certificate + chain, PKCS#7"))
    if r.get("key"):
        files.append((f"{n}.key", "application/x-pem-file", b64(r["key"]), "private key, PEM (unencrypted)"))
    if r.get("p12_b64"):
        files.append((f"{n}.p12", "application/x-pkcs12", r["p12_b64"], "certificate + key + chain, PKCS#12"))
    title = {"sign": "Certificate signed", "issue": "Key and certificate generated",
             "convert": "Certificate converted"}[kind]
    return render_page("pki_result", ctx=ctx, page="/pki", title=title, r=r, files=files, back=kind)
