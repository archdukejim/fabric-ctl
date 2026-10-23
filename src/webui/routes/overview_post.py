import urllib.parse

from webui import agentclient as actions


def overview_post(h, parts):
    """Purpose: The Overview's jobs (2.1.8.3): run doctor's checks, or update / roll back one service's image; each
             starts a fabric-agent job and sends the person to its page.
    Inputs:  h — the request handler (redirect, back, deny); parts — segments after /overview/: ['doctor'] or ['images',
             <service>, 'update'|'rollback'].
    Returns: 303 to /jobs/<id>; a refusal: 303 back to Doctor or Updates with why.
    Fails:   404 for another path; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/overview/…)."""
    back = "/overview/updates" if parts[:1] == ["images"] else "/overview/doctor"
    try:
        if parts == ["doctor"]:
            job = actions.start_job("doctor")
        elif len(parts) == 3 and parts[0] == "images" and parts[2] in ("update", "rollback"):
            job = actions.start_job("images", {"action": parts[2], "service": parts[1]})
        else:
            return h.deny(404, "Not found.")
    except actions.ValidationError as exc:
        return h.back(back, err=str(exc))
    return h.redirect("/jobs/" + urllib.parse.quote(job, safe=""))
