import re
import time

from webui import agentclient as actions
from webui import views
from webui.constants import STEP_UP

PREFIX = "/settings/backups/download/"


def backups_page(h, sess, ctx, path, query):
    """Purpose: the Backups page (manual 1.3.7.9): GET /settings/backups shows the list, Back up now, the schedule, or a
             bundle's Restore (?restore=<file>[&section=<name>]); GET /settings/backups/download/<file> streams the
             bundle as it is.
    Inputs:  h — the request handler (send, send_stream, deny); sess — dict from find_session (auth_at); ctx — page
             context; path — the path; query — dict: restore, section.
    Returns: 200 the page; 200 the file (application/octet-stream, an attachment); 404 for another path or a name
             that is not a bundle's.
    Fails:   agent errors propagate to handle_request (400: not a Domain Admin, the DC down; 503 the agent down).
    Feeds:   get_page."""
    if path.startswith(PREFIX):
        name = path[len(PREFIX):]
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
            return h.deny(404, "Not found.")
        try:
            stream, length = actions.backup_download(name)
        except actions.NotFound:
            return h.deny(404, f"No bundle {name}.")
        try:
            return h.send_stream(stream, length, "application/octet-stream",
                                 [("Content-Disposition", f'attachment; filename="{name}"')])
        finally:
            stream.close()
    if path == "/settings/backups":
        return h.send(200, views.backups(ctx, actions.backup_overview(), query.get("restore", ""),
                                         query.get("section", ""),
                                         signin_old=time.time() - sess.get("auth_at", 0) > STEP_UP))
    return h.deny(404, "Not found.")
