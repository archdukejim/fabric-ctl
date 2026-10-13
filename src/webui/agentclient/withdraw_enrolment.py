from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def withdraw_enrolment(actor, cid):
    """Purpose: Withdraw an Apple profile's one-time challenge before it is used (manual 1.5.3.7).
             Agent route: POST /v1/pki/enrolments/<id>/withdraw (pki:enrol; another person's needs pki:revoke).
    Inputs:  actor — str user name; cid — the challenge's id.
    Returns: {"id", "cn"}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: unknown, used,
             expired, or another person's), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/enrol_post for "<id>/withdraw".
    """
    return call_agent("POST", f"/v1/pki/enrolments/{quote_segment(cid)}/withdraw", {"actor": actor})
