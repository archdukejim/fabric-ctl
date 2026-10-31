from webui import agentclient as actions


def saved_and_applied(h, page, change):
    """Purpose: Run a change that fabric-agent saves and applies at once, and go back to its page with the outcome.
    Inputs:  h — the request handler (back, deny); page — the page to go back to (/kea, /8021x); change — a function
             returning (agent result with "applied" and "output", the message to show), or None for an unknown path.
    Returns: 303 to the page with the message; with why when applying failed (the last 300 characters of its output)
             or the agent refused the input; 404 when change returned None.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   kea_post (DHCP), post_action (802.1X people)."""
    try:
        done = change()
        if done is None:
            return h.deny(404, "Not found.")
        res, msg = done
        if not res.get("applied"):
            return h.back(page, err=msg + " Saved, but applying failed: " + res.get("output", "")[-300:])
    except actions.ValidationError as exc:
        return h.back(page, err=str(exc))
    return h.back(page, msg=msg)
