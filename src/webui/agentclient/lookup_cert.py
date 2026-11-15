from webui.agentclient.connection import call_agent


def lookup_cert(actor, serial="", pem=""):
    """Purpose: The certificate a revocation names, by its serial or the certificate itself, before its confirmation
             (manual 1.5.1.9.2). Agent route: POST /v1/pki/lookup (pki:read), timeout 60 s.
    Inputs:  actor — str user name; serial — hex; pem — a PEM or base64 DER certificate (one of the two).
    Returns: the Issued list's row for it (fabriclib.pki.find_cert).
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: not a certificate, not signed by this CA,
             the CA's own, an unknown serial), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/stepca_post ("revoke/review")."""
    return call_agent("POST", "/v1/pki/lookup", {"actor": actor, "serial": serial, "pem": pem}, timeout=60)
