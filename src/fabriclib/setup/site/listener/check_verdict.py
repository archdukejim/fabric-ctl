def check_verdict(name_seen, reached, console_ok, host_problem, name):
    """Purpose: the finish's check, in words (manual 1.3.6.6): whether the console's name resolves here from the
             person's
             computer and answers with a certificate it trusts, saying which of the two failed. A TLS hello naming it
             that reached this site proves the name resolves here; the request arriving past TLS proves the browser
             trusts the certificate.
    Inputs:  name_seen — the site saw a TLS hello from this client naming the console; reached — the check's request
             came through; console_ok — the browser's request to the console itself succeeded; host_problem — what
             the host's own check found wrong (str, "" for nothing); name — the console's name.
    Returns: {"ok": bool, "failed": "", "dns", "trust" or "console", "text": str}.
    Fails:   never.
    Feeds:   listener/request_handler."""
    if not name_seen:
        return {"ok": False, "failed": "dns",
                "text": f"{name} does not lead here from your computer: the name did not resolve to this host. Do the "
                        "DNS step, then check again."}
    if not reached:
        return {"ok": False, "failed": "trust",
                "text": f"{name} resolves here, but your browser does not trust the certificate. Do the trust step and "
                        "restart the browser, then check again."}
    if host_problem or not console_ok:
        return {"ok": False, "failed": "console",
                "text": f"{name} resolves here and your browser trusts fabric's certificate, but the console did not "
                        f"answer{': ' + host_problem if host_problem else ''}. sudo fabricctl doctor says more."}
    return {"ok": True, "failed": "",
            "text": f"{name} resolves here and answers with a certificate your browser trusts."}
