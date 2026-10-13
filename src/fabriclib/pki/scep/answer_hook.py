import urllib.parse

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.pki.scep.check_challenge import check_challenge
from fabriclib.pki.scep.constants import CHALLENGE_PATH, CHALLENGES_FILE, ISSUED_PATH, STEPCA_OWN_NAMES
from fabriclib.pki.scep.record_scep_issue import record_scep_issue


def _is_stepca(v, verify, escaped_pem):
    """Purpose: whether the caller is this site's Step-CA: nginx verified its client certificate against this CA, and
             the certificate is Step-CA's own TLS certificate (its names: hostname_stepca, localhost, 127.0.0.1 — no
             service certificate carries the last two).
    Inputs:  v — settings (hostname_stepca); verify — nginx's $ssl_client_verify; escaped_pem — nginx's
             $ssl_client_escaped_cert (URL-encoded PEM).
    Returns: (bool, why) — why says what was missing.
    Fails:   never: an unreadable certificate is refused.
    Feeds:   answer_hook."""
    if verify != "SUCCESS":
        return False, f"no verified client certificate ({verify or 'none'})"
    try:
        sans = describe_cert(urllib.parse.unquote(escaped_pem or ""))["sans"]
    except ValidationError:
        return False, "the client certificate cannot be read"
    wanted = (f"DNS:{v.get('hostname_stepca', '')}".lower(), *(n.lower() for n in STEPCA_OWN_NAMES))
    have = {s.lower() for s in sans}
    missing = [w for w in wanted if w not in have]
    return (False, "not Step-CA's own certificate (missing " + ", ".join(missing) + ")") if missing else (True, "")


def answer_hook(v, path, verify, escaped_pem, body, store=CHALLENGES_FILE, **issue_kw):
    """Purpose: answer one of Step-CA's SCEP webhooks (manual 1.5.3.3): only Step-CA itself may ask; the challenge hook
             says whether a request may be signed, the notification hook records what was issued.
    Inputs:  v — settings; path — the request path (CHALLENGE_PATH or ISSUED_PATH); verify, escaped_pem — nginx's
             verification result and client certificate (X-SSL-Client-Verify, X-SSL-Client-Cert); body — the parsed
             JSON body (dict); store — the challenge store; issue_kw — record_scep_issue's ledger and link (tests).
    Returns: (status, answer): (200, {"allow": True}) or (200, {"allow": False, "error": {"code", "message"}}) for the
             challenge; (200, {"allow": True, ...record}) for a notification; (403, {"error"}) when the caller is not
             Step-CA (audited SCEP_HOOK_REFUSED); (404, {"error"}) for another path; (400, {"error"}) for a body that
             is not an object.
    Fails:   OSError / ValueError from the store or the ledger; ValidationError from record_scep_issue (a notification
             without a readable certificate) — the server answers 500/400, Step-CA then refuses or logs it.
    Feeds:   src/scephook/server.py (fabric-scep-hook, behind nginx on hostname_mgr)."""
    if path not in (CHALLENGE_PATH, ISSUED_PATH):
        return 404, {"error": "not found"}
    ok, why = _is_stepca(v, verify, escaped_pem)
    if not ok:
        write_audit("-", "SCEP_HOOK_REFUSED", f"{path}: {why}", "scep")
        return 403, {"error": "only fabric's Step-CA may call this"}
    if not isinstance(body, dict):
        return 400, {"error": "the body is not a JSON object"}
    if path == CHALLENGE_PATH:
        allow, reason = check_challenge(body, store=store)
        return 200, ({"allow": True} if allow else {"allow": False, "error": {"code": "fabric-challenge",
                                                                              "message": reason}})
    return 200, {"allow": True, **record_scep_issue(v, body, store=store, **issue_kw)}
