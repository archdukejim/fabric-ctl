from webui.agentclient.connection import call_agent


def hold_change(route, body=None):
    """Purpose: Hold a change on its page until that page's Apply (manual 1.8.6.5), instead of doing it now.
             Agent route: POST /v1/pending/hold (any sign-in; the change's own permission is checked now and at Apply).
    Inputs:  route — the change's agent route after /v1/ (e.g. "people/sam/disable", its segments already quoted);
             body — the change's JSON body (dict).
    Returns: {"id", "page", "what", "pending"}: the change in a sentence and how many wait on its page.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: the change not held, its permission missing,
             the thing unreadable now), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/directory_post.
    """
    return call_agent("POST", "/v1/pending/hold", {"route": route, "body": body or {}})
