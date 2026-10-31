from webui import agentclient as actions
from webui.views.constants import PENDING_PAGES


def changes_post(h, parts, form):
    """Purpose: A page's pending changes (manual 1.8.6.5): Apply them as one job, Discard them, or Drop one.
    Inputs:  h — the request handler (back, deny); parts — segments after /changes/: [<page id>, "apply" | "discard" |
             "drop"]; form — dict (drop: id).
    Returns: 303: apply to the page's Review (its queue shows the job, refreshing while it runs); discard to the page
             itself; drop to the Review; each with what was done, or why not, as its message.
    Fails:   404 for an unknown page or operation; AgentError, PermissionDenied and AuthError propagate.
    Feeds:   post_action (/changes/...).
    """
    if len(parts) != 2 or parts[0] not in PENDING_PAGES or parts[1] not in ("apply", "discard", "drop"):
        return h.deny(404, "Not found.")
    page, op = parts
    review = f"/changes/{page}"
    try:
        if op == "apply":
            actions.pending_action(page, "apply")
            return h.back(review, msg="Applying: each change's progress is below.")
        if op == "discard":
            done = actions.pending_action(page, "discard")
            return h.back(PENDING_PAGES[page], msg=f"Discarded {done['dropped']} pending change(s).")
        done = actions.pending_action(page, "drop", form.get("id", ""))
        return h.back(review, msg=f"Dropped; {done['pending']} still pending.")
    except actions.ValidationError as exc:
        return h.back(review, err=str(exc))
