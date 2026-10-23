from webui.views.constants import JOB_PAGES
from webui.views.render_page import render_page


def job_page(ctx, job):
    """Purpose: A background job the person started (2.1.8.3): doctor's checks with each result, or an image update or
             rollback with what it did; while it runs the page reloads itself every 2 seconds (a meta refresh: no
             script, the strict CSP holds).
    Inputs:  ctx — page context; job — read_job() dict (kind, state, result, error).
    Returns: HTML str.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/get_page (/jobs/<id>); devserver."""
    return render_page("job", ctx=ctx, page=JOB_PAGES.get(job.get("kind"), "/"), job=job)
