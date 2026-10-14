from webui.views.render_page import render_page


def federation(ctx, overview, msg="", err="", lost=None, dc_token=None):
    """Purpose: The Federation tab: this site's place, the sites that joined here, its DC's replication and conflict
             objects, the write limits, the roles granted at this site and the sites below it (with the grant and revoke
             form for federation:admin, 2.1.9.21) and the address plan (this site's and the sites' below it, 2.1.9.22);
             a pending change of this site's DC type (2.1.9.23) and, for federation:admin, the form that asks a site
             below for one; a lost read-only DC's accounts and the form to handle it (2.1.6.58).
    Inputs:  ctx — page context; overview — federation_overview() dict; msg, err — str shown at the top; lost — None
             or {"site", plan_rodc_lost's answer}; dc_token — None, or request_dc_type's answer just made (its change
             token shown this once, never stored or put in a URL).
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/federation_page (/federation); devserver.
    """
    return render_page("federation", ctx=ctx, tab="federation", f=overview, msg=msg, err=err, lost=lost,
                       dc_token=dc_token)
