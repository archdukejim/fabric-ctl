from webui.views.render_page import render_page


def dhcp_options(ctx, overview, target="", msg="", err=""):
    """Purpose: The DHCP options page (manual 1.10.4.24.6): built to drop into the Networks tab, shown under the Kea tab
             until then.
    Inputs:  ctx — page context; overview — option_sets()'s dict (org, site_options, settings, subnets, org_editable,
             org_editors, root, catalogue, effective); target — the target shown ("" none); msg, err — flash texts.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads a value the caller left out).
    Feeds:   src/webui/routes/options_page; devserver."""
    return render_page("dhcp_options", ctx=ctx, tab="kea", d=overview, target=target, msg=msg, err=err)
