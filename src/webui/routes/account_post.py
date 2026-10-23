from webui import agentclient as actions
from webui.routes.held import held, q


def account_post(h, parts, form):
    """Purpose: My account's forms (manual 1.8.6.6): the person's own password, changed at once (never pending,
             2.1.8.11); a member added to or removed from a group they manage, held for My account's Apply (1.8.6.5).
    Inputs:  h — the request handler (back, deny); parts — segments after /account/: ["password"] or ["groups",
             <group>, "members"]; form — dict (password: current, new, again; members: action add|remove, member).
    Returns: 303 to /account (the password: changed, or why not; never a password in the message) or /account/groups
             (held's message).
    Fails:   404 for another form; AgentError, PermissionDenied and AuthError propagate.
    Feeds:   post_action (/account/...)."""
    if parts == ["password"]:
        current, new, again = form.get("current", ""), form.get("new", ""), form.get("again", "")
        if not current or not new:
            return h.back("/account", err="Type your current password and the new one.")
        if new != again:
            return h.back("/account", err="The new password and its repeat differ: nothing was changed.")
        try:
            done = actions.change_own_password(current, new)
        except actions.ValidationError as exc:
            return h.back("/account", err=str(exc))
        ended = done.get("sessions_ended") or 0
        return h.back("/account", msg="Your password is changed." + (
            f" Your {ended} other session(s) were signed out." if ended else ""))
    if len(parts) == 3 and parts[0] == "groups" and parts[2] == "members":
        return held(h, "/account/groups", f"account/groups/{q(parts[1])}/members",
                    {"action": form.get("action", ""), "member": form.get("member", "")})
    return h.deny(404, "Not found.")
