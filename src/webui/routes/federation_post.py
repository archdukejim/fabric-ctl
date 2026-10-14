import urllib.parse

from webui import agentclient as actions


def federation_post(h, form):
    """Purpose: the Federation tab's role form (POST /federation/roles, manual 1.9.8.20, decision 2.1.9.21): one
             fabric-agent call that grants a role at a site below this one, or takes it back; then back to the tab
             with what it did, or why it was refused.
    Inputs:  h — the request handler (redirect); form — dict: site, role ("admins" too for remake), member ("" for
             the site's own admins), action grant|revoke|remake (the site's group made again, 2.3.9.2.8).
    Returns: 303 to /federation with msg or err.
    Fails:   AgentError, PermissionDenied (no federation:admin) and AuthError propagate to handle_request.
    Feeds:   post_action."""
    try:
        done = actions.site_role_change(form.get("site", ""), form.get("role", ""), form.get("member", ""),
                                        form.get("action", ""))
    except actions.ValidationError as exc:
        return h.redirect("/federation?" + urllib.parse.urlencode({"err": str(exc)}))
    if form.get("action") == "remake":
        what = ("replaced (the site had made it itself)" if done.get("remade") else "made (it was missing)"
                if done.get("made") else "left as it is (fabric made it)")
        return h.redirect("/federation?" + urllib.parse.urlencode({"msg": f"group {done['group']} {what}."}))
    msg = (f"{done['role']} at {done['site']} {'granted to' if done['granted'] else 'revoked from'} {done['member']}"
           + ("." if done["changed"] else " (no change).")
           + (" The group the site had made itself was replaced." if done.get("remade") else ""))
    return h.redirect("/federation?" + urllib.parse.urlencode({"msg": msg}))
