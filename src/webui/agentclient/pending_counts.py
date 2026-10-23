from webui.agentclient.connection import call_agent


def pending_counts():
    """Purpose: The signed-in person's pending changes per page, and the pages with an apply running they may see
             (the top bar and the navigation, manual 1.8.6.5). Agent route: GET /v1/pending (any sign-in).
    Inputs:  none.
    Returns: {page id: {"pending": n, "running": bool}}.
    Fails:   the call_agent exceptions.
    Feeds:   src/webui/session/page_context.
    """
    return call_agent("GET", "/v1/pending")
