from webui.views.render_page import render_page


def federation(ctx, overview, msg="", err=""):
    """Purpose: The Federation tab: this site's place, the sites that joined here, its DC's replication and conflict
             objects, the write limits, the roles granted at this site and the sites below it (with the grant and revoke
             form for federation:admin, 2.1.9.21) and the address plan (this site's and the sites' below it, 2.1.9.22).
    Inputs:  ctx — page context; overview — federation_overview() dict; msg, err — flash text after a grant or revoke.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/get_page (/federation); devserver.
    """
    return render_page("federation", ctx=ctx, tab="federation", f=overview, msg=msg, err=err)
