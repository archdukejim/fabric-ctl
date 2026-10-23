from webui import agentclient as actions
from webui.views.constants import PENDING_PAGES


def page_context(sess):
    """Purpose: The page context every view needs: who is signed in, the CSRF token, their permissions and the
             installed version.
    Inputs:  sess — dict from find_session.
    Returns: {'user': str, 'csrf': str, 'perms': list, 'version': actions.version_info(), 'reminders': the host's
             reminders from the sign-in (finish_login; list of {kind, text}), 'flash': the last action's message
             ({"ok"} or {"err"}, Handler.back; None), 'preview': True only in the dev preview (its banner),
             'pending': {navigation page path: {"id", "pending", "running"}} (Apply per page, 1.8.6.5: the person's
             own pending changes, and whether an apply of the page is running; empty when fabric-agent cannot say),
             'pending_counts': {path: pending} (the navigation's marks)}.
    Fails:   agent errors (ValidationError, AuthError, PermissionDenied, AgentError) from version_info propagate to
             handle_request (400, redirect to /login, 403, 503).
    Feeds:   every route in src/webui/routes → every page in src/webui/views.
    """
    try:
        counts = actions.pending_counts()
    except (actions.AgentError, actions.ValidationError, actions.PermissionDenied):
        counts = {}                       # the frame without its pending marks: the page itself still works
    pending = {PENDING_PAGES[k]: {"id": k, **v} for k, v in counts.items() if k in PENDING_PAGES}
    return {"user": sess["user"], "csrf": sess["csrf"], "perms": sess.get("perms") or [],
            "version": actions.version_info(), "reminders": sess.get("reminders") or [],
            "flash": sess.get("flash"), "preview": bool(sess.get("preview")), "pending": pending,
            "pending_counts": {path: p["pending"] for path, p in pending.items()}}
