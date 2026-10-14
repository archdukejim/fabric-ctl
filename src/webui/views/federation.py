from webui.views.render_page import render_page


def federation(ctx, overview, msg="", err="", lost=None):
    """Purpose: The Federation tab: this site's place, the sites that joined here, its DC's replication and conflict
             objects, the write limits and the address plan; a pending change of this site's DC type (2.1.9.23); a lost
             read-only DC's accounts and the form to handle it (2.1.6.58).
    Inputs:  ctx — page context; overview — federation_overview() dict; msg, err — str shown at the top; lost — None
             or {"site", plan_rodc_lost's answer}.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/federation_page (/federation); devserver.
    """
    return render_page("federation", ctx=ctx, tab="federation", f=overview, msg=msg, err=err, lost=lost)
