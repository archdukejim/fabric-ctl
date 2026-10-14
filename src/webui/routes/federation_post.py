import urllib.parse

from webui import agentclient as actions


def federation_post(h, form):
    """Purpose: the Federation tab's role form (POST /federation/roles, manual 1.9.8.20, decision 2.1.9.21): one
             fabric-agent call that grants a role at a site below this one, or takes it back; then back to the tab
             with what it did, or why it was refused.
    Inputs:  h — the request handler (redirect); form — dict: site, role, member ("" for the site's own admins),
             action grant|revoke.
    Returns: 303 to /federation with msg or err.
    Fails:   AgentError, PermissionDenied (no federation:admin) and AuthError propagate to handle_request.
    Feeds:   post_action."""
    try:
        done = actions.site_role_change(form.get("site", ""), form.get("role", ""), form.get("member", ""),
                                        form.get("action", ""))
    except actions.ValidationError as exc:
        return h.redirect("/federation?" + urllib.parse.urlencode({"err": str(exc)}))
    msg = (f"{done['role']} at {done['site']} {'granted to' if done['granted'] else 'revoked from'} {done['member']}"
           + ("." if done["changed"] else " (no change)."))
    return h.redirect("/federation?" + urllib.parse.urlencode({"msg": msg}))
