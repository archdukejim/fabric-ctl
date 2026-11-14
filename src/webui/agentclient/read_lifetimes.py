from webui.agentclient.connection import call_agent


def read_lifetimes():
    """Purpose: PKI → Lifetimes' values, limits and next renewals (decision 2.1.5.14).
             Agent route: GET /v1/pki/lifetimes (pki:read).
    Inputs:  none.
    Returns: fabriclib.pki.read_lifetimes' dict: values, intermediate_left_days, authority_max_hours, notes, renewals,
             machines_expiring, acme_client.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/lifetimes_page."""
    return call_agent("GET", "/v1/pki/lifetimes")
