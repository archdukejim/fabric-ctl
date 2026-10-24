from webui.agentclient.connection import call_agent


def site_tree():
    """Purpose: the top bar's site selector (decision 2.1.8.30, manual 1.8.6.12): every site of the domain nested
             under its parent, each with its console's address and its health.
             Agent route: GET /v1/sites/tree (permission: session).
    Inputs:  none.
    Returns: {"site", "tree": [{"site", "parent", "console", "here", "state", "why", "replication", "children"}],
             "error"} (fabriclib.federation.site_selector).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/session/page_context (every page's top bar), src/webui/routes/site_link (/sites/<name>)."""
    return call_agent("GET", "/v1/sites/tree")
