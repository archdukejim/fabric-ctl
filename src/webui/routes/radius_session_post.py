import urllib.parse

from webui import agentclient as actions


def radius_session_post(h, parts, form):
    """Purpose: a session's Disconnect, Re-authenticate or Move VLAN (CoA to its switch, manual 1.11.1.4): sent at
             once; the answer, or why it was refused, shown on the Sessions view.
    Inputs:  h — the request handler (redirect, deny); parts — path segments after /freeradius/sessions: ['disconnect'],
             ['reauthenticate'] or ['bounce']; form — dict from read_form (client, session).
    Returns: 303 to /freeradius?view=sessions with msg (acknowledged) or err (refused, NAK, no answer).
    Fails:   404 for other paths; AgentError, PermissionDenied (no radius:coa) and AuthError propagate to
             handle_request.
    Feeds:   post_action (/freeradius/sessions/…).
    """
    if len(parts) != 1 or parts[0] not in ("disconnect", "reauthenticate", "bounce"):
        return h.deny(404, "Not found.")
    try:
        res = actions.coa_session(parts[0], form.get("client", ""), form.get("session", ""))
    except actions.ValidationError as exc:
        return h.redirect("/freeradius?" + urllib.parse.urlencode({"view": "sessions", "err": str(exc)}))
    return h.redirect("/freeradius?" + urllib.parse.urlencode({"view": "sessions", "msg": res.get("message", "")}))
