from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def pending_page(page):
    """Purpose: A page's Review (manual 1.8.6.5): the person's changes waiting on it (old and new values), the page's
             queue (every apply, change by change) and results to show them once. Agent route: GET
             /v1/pending/<page> (any sign-in; the queue only with the page's own read permission).
    Inputs:  page — a pending page id ("people", "groups", "machines", "policies", ...).
    Returns: {"page", "changes", "queue", "shown_once"}.
    Fails:   the call_agent exceptions (404 as NotFound for an unknown page).
    Feeds:   src/webui/routes/get_page (/changes/<page>).
    """
    return call_agent("GET", f"/v1/pending/{quote_segment(page)}")
