import re

from webui import agentclient as actions

BACK_RE = re.compile(r"^/[A-Za-z0-9/_.%?=&-]*$")


def kept_post(h, form):
    """Purpose: A page's Refresh (manual 1.8.9.4, decision 2.1.8.45): read its data again now, then show it.
    Inputs:  h — the request handler (back, redirect); form — {"read": the agent's route, "back": the page's own path}.
    Returns: 303 back to the page, with what was refused or a failed read's reason shown on it; a `back` that is not
             a path on this site goes to /.
    Fails:   PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action."""
    back = form.get("back", "")
    if not BACK_RE.match(back) or back.startswith("//"):
        back = "/"
    try:
        out = actions.kept_refresh(form.get("read", ""))
    except (actions.AgentError, actions.ValidationError) as exc:
        return h.back(back, err=str(exc))
    if out.get("failed"):
        return h.back(back, err=f"The refresh failed: {out['failed']}")
    return h.redirect(back)
