from webui.agentclient.connection import call_agent


def list_certs():
    """Purpose: Every certificate the console can revoke, for PKI's Issued view (decision 2.1.5.13).
             Agent route: GET /v1/pki/certs (pki:read), timeout 60 s (Step-CA's database is copied and read).
    Inputs:  none.
    Returns: {"certs": [{serial, subject, cn, sans, not_after, status, source, revocable, ...}], "stepca_error",
             "directory_error", "sources": {source: label}} (fabriclib.pki.certs_overview).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/stepca_page (views "issued" and "cert")."""
    return call_agent("GET", "/v1/pki/certs", timeout=60)
