from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def pending_action(page, op, change_id=None):
    """Purpose: Apply a page's pending changes as one job, discard them, or drop one (manual 1.8.6.5). Agent routes:
             POST /v1/pending/<page>/apply, /discard, /drop (body: id) (any sign-in; each change's own permission
             checked again at Apply).
    Inputs:  page — a pending page id; op — "apply", "discard" or "drop"; change_id — the change for drop.
    Returns: apply: {"id"} (the job); discard and drop: {"dropped", "pending"}.
    Fails:   the call_agent exceptions: ValidationError (400: nothing pending, an apply still running, no such
             change).
    Feeds:   src/webui/routes/changes_post.
    """
    return call_agent("POST", f"/v1/pending/{quote_segment(page)}/{op}", {"id": change_id} if change_id else {})
