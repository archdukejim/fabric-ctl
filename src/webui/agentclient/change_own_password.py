from webui.agentclient.connection import call_agent


def change_own_password(current, new):
    """Purpose: The signed-in person's own password changed at once, never pending (manual 1.8.6.6, 1.6.12.17.9):
             AD checks the current one, the policy and the history; their other sessions end. Agent route: POST
             /v1/account/password (any sign-in, their own). Both passwords go in the request body only.
    Inputs:  current — the current password; new — the new one.
    Returns: {"uid", "changed", "sessions_ended"}.
    Fails:   the call_agent exceptions: ValidationError (400: a wrong current password, one AD's policy refuses, the
             same as the current one).
    Feeds:   src/webui/routes/account_post.
    """
    return call_agent("POST", "/v1/account/password", {"current": current, "new": new})
