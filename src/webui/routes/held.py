import urllib.parse

from webui import agentclient as actions


def q(segment):
    """Purpose: One agent route segment, quoted (a name with a slash cannot reach another route).
    Inputs:  segment — str.
    Returns: str.
    Fails:   never.
    Feeds:   held's callers (directory_post, account_post)."""
    return urllib.parse.quote(str(segment), safe="")


def held(h, back, route, body=None):
    """Purpose: Hold a change on its page until the page's Apply (manual 1.8.6.5), and go back to the page saying so.
    Inputs:  h — the request handler (back); back — the page to return to; route — the change's agent route after
             /v1/ (segments quoted with q); body — its JSON body.
    Returns: 303 to back, with "Waiting for Apply: <the change>" or the refusal (a missing permission, the thing
             unreadable now) as its message.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   directory_post, account_post."""
    try:
        done = actions.hold_change(route, body or {})
    except actions.ValidationError as exc:
        return h.back(back, err=str(exc))
    return h.back(back, msg=f"Waiting for Apply: {done['what']} ({done['pending']} pending on this page).")
