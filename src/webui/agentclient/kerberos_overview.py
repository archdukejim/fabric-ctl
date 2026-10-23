from webui.agentclient.connection import call_agent


def kerberos_overview():
    """Purpose: The Kerberos page's facts (manual 1.6.12.9): whether sign-in with the domain logon is on, the realm and
             its KDCs, the ticket policy as set.
             Agent route: GET /v1/domain/kerberos (domain:read).
    Inputs:  none.
    Returns: {"realm", "kdcs": [DC names] or None, "kdcs_error", "policy": {"ticket_hours", "renew_days",
             "skew_minutes"}, "signin_kerberos": bool}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/kerberos_page (/directory/kerberos).
    """
    return call_agent("GET", "/v1/domain/kerberos")
