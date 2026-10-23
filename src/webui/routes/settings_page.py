import re
import time

from webui import agentclient as actions
from webui import views
from webui.constants import STEP_UP


def settings_page(h, sess, ctx, path, query):
    """Purpose: the setup wizard's pages (manual 1.8.5.3): GET /settings shows a step (?step=, the first by default)
             filled in with today's settings; GET /settings/export downloads the settings file.
    Inputs:  h — the request handler (send, deny); sess — dict from find_session (auth_at: whether Apply will ask for a
             new sign-in); ctx — page context; path — "/settings" or "/settings/export"; query — dict: step.
    Returns: 200 the page; 200 a YAML attachment for the export; 404 for another path.
    Fails:   agent errors propagate to handle_request (403 without settings:admin, 503 the agent down).
    Feeds:   get_page."""
    if path == "/settings/export":
        res = actions.settings_export()
        name = re.sub(r"[^A-Za-z0-9._-]", "_", str(res.get("name") or "settings.yaml"))
        return h.send(200, res["text"], "text/yaml; charset=utf-8",
                      [("Content-Disposition", f'attachment; filename="{name}"')])
    if path == "/settings":
        return h.send(200, views.settings(ctx, actions.settings_overview(), query.get("step", "parts"), None,
                                          "", "",
                                          signin_old=time.time() - sess.get("auth_at", 0) > STEP_UP))
    return h.deny(404, "Not found.")
