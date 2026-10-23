from webui.views.render_page import render_page


def settings_plan(ctx, plan, msg="", err=""):
    """Purpose: a plan of the setup wizard (manual 1.8.5.5): each changed setting old → new, the parts started or
             stopped, the memory plan, what a file's import ignored and why; nothing has changed yet. Apply (one
             apply job) needs a sign-in from the last 5 minutes; Back returns to the wizard.
    Inputs:  ctx — page context; plan — settings_plan() (id, changes, parts, memory, ignored, source); msg, err —
             flash texts (a stale plan made again is said in err).
    Returns: HTML str.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/settings_post (/settings/plan, /settings/import, a stale /settings/apply)."""
    return render_page("settings_plan", ctx=ctx, page="/settings", plan=plan, msg=msg, err=err)
