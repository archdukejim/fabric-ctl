from webui.agentclient.connection import call_agent


def revoke_cert(actor, target, reason, pem="", confirm=""):
    """Purpose: Revoke a certificate fabric issued (manual 2.1.5.10); the CRLs are published at once.
             Agent route: POST /v1/pki/revoke (pki:revoke), timeout 120 s.
    Inputs:  actor — str user name; target — a serial or a certificate's name; reason — one of the CRL reasons;
             pem — the certificate itself, when the person gave it (1.5.1.9.2); confirm — the name typed again (the
             certificate's CN, or its serial when it has none, 1.5.1.9.3).
    Returns: dict from fabriclib.pki.revoke_cert: {"serial", "subject", "issuer", "reason", "replaced"} (replaced: the
             services that took a new certificate first, for one of fabric's own, 1.5.1.9.4).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: unknown reason
             or certificate, not signed here, the CA's own, the name not typed again, already revoked, a service
             certificate whose successor could not be issued), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/stepca_post for "revoke".
    """
    return call_agent("POST", "/v1/pki/revoke", {"actor": actor, "target": target, "reason": reason, "pem": pem,
                                                 "confirm": confirm}, timeout=300)
