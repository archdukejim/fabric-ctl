from webui.views.render_page import render_page


def directory(ctx, overview=None, unavailable=""):
    """Purpose: The Directory's Overview (manual 1.6.12.3): the domain, its DCs, replication, the sites and the counts
             linking to their pages.
    Inputs:  ctx — page context; overview — directory_overview()'s dict; unavailable — why it could not be read.
    Returns: HTML str, in the navigation's Directory Overview page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/directory_page; devserver.
    """
    return render_page("directory", ctx=ctx, page="/directory", overview=overview or {}, unavailable=unavailable)
