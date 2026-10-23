from webui.views.constants import PENDING_PAGES
from webui.views.render_page import render_page


def changes(ctx, data):
    """Purpose: A page's Review (manual 1.8.6.5): the person's changes waiting for the page's Apply, each with what it
             changes (old and new values) and a Drop; Apply and Discard; the page's queue as a stream (every apply,
             change by change: queued, running, done or failed with why), refreshing itself while one runs; and the
             results to show once (a new person's or machine's one-time password).
    Inputs:  ctx — page context; data — pending_page's dict {"page", "changes", "queue", "shown_once"}.
    Returns: HTML str, in the navigation's page whose changes these are.
    Fails:   KeyError for a page id not in PENDING_PAGES; Jinja2 errors propagate.
    Feeds:   src/webui/routes/get_page (/changes/<page>).
    """
    running = any(a.get("state") == "running" for a in data.get("queue") or [])
    return render_page("changes", ctx=ctx, page=PENDING_PAGES[data["page"]], d=data, page_id=data["page"],
                       refresh=running)
