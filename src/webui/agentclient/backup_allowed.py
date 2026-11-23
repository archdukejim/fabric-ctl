from webui.agentclient.connection import call_agent


def backup_allowed():
    """Purpose: whether the signed-in person may see the Backups page (manual 1.3.7.9): a Domain Admin. Asked once per
             sign-in, for the navigation; fabric-agent checks again at every backup route. Agent route:
             GET /v1/backup/allowed (any sign-in).
    Inputs:  none (the thread's token).
    Returns: True or False.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: the DC not answering), AuthError,
             PermissionDenied.
    Feeds:   src/webui/session/finish_login."""
    return bool(call_agent("GET", "/v1/backup/allowed").get("allowed"))
