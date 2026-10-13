from webui.agentclient.connection import call_agent


def list_enrolments():
    """Purpose: Open Apple profiles and the certificates issued by enrolment (manual 1.5.3.7).
             Agent route: GET /v1/pki/enrolments (pki:read).
    Inputs:  none.
    Returns: {"challenges": [{id, by, made, expires, cn, device}], "issued": [ledger entries with status and
             link_error]}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/stepca_page (view "enrol").
    """
    return call_agent("GET", "/v1/pki/enrolments")
