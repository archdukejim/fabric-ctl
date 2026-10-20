from webui import agentclient as actions


def page_context(sess):
    """Purpose: The page context every view needs: who is signed in, the CSRF token, their permissions and the
             installed version.
    Inputs:  sess — dict from find_session.
    Returns: {'user': str, 'csrf': str, 'perms': list, 'version': actions.version_info(), 'reminders': the host's
             reminders from the sign-in (finish_login; list of {kind, text})}.
    Fails:   agent errors (ValidationError, AuthError, PermissionDenied, AgentError) from version_info propagate to
             handle_request (400, redirect to /login, 403, 503).
    Feeds:   every route in src/webui/routes → every page in src/webui/views.
    """
    return {"user": sess["user"], "csrf": sess["csrf"], "perms": sess.get("perms") or [],
            "version": actions.version_info(), "reminders": sess.get("reminders") or []}
