from webui import agentclient as actions


def finish_setting_up(h, sess, ctx):
    """Purpose: the setup wizard on the Overview (manual 1.8.5.3): for someone with settings:admin, whether it is
             finished (applied once or dismissed); until it is, the first Overview of each sign-in opens the wizard
             (once: the session remembers it), and the Overview shows Finish setting up.
    Inputs:  h — the request handler (app: its sessions and lock); sess — dict from find_session (sid,
             wizard_opened); ctx — page context (perms).
    Returns: (wizard, open_now): wizard — {"finished", ...} or None (no settings:admin, or the agent could not say);
             open_now — True when the wizard should open now (the session is marked).
    Fails:   AuthError and PermissionDenied propagate to handle_request; AgentError and ValidationError give None.
    Feeds:   get_page (/)."""
    if "settings:admin" not in (ctx.get("perms") or []):
        return None, False
    try:
        wizard = actions.settings_overview()["finished"]
    except (actions.AgentError, actions.ValidationError):
        return None, False
    if wizard["finished"] or sess.get("wizard_opened"):
        return wizard, False
    with h.app.lock:
        stored = h.app.sessions.get(sess.get("sid"))
        if stored is not None:
            stored["wizard_opened"] = True
    return wizard, True
