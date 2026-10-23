from webui.views.render_page import render_page


def federation(ctx, overview):
    """Purpose: The Federation tab: this site's place, the sites that joined here, its DC's replication and conflict
             objects, the write limits and the address plan.
    Inputs:  ctx — page context; overview — federation_overview() dict.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/get_page (/federation); devserver.
    """
    return render_page("federation", ctx=ctx, page="/federation", f=overview)
