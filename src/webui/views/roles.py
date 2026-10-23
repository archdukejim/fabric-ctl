from webui.views.render_page import render_page


def roles(ctx, view, data=None, role=None, unavailable=""):
    """Purpose: 802.1X · Device roles (manual 2.1.8.10, 1.8.6.3): the list, Add device role, or one role's page (what it
             grants, its devices linked, Edit and Remove); every change held for the Device roles page's Apply
             (1.8.6.5).
    Inputs:  ctx — page context; view — "list", "new" or "role"; data — device_overview(); role — the role shown;
             unavailable — why the roles could not be read.
    Returns: HTML str, in the navigation's Device roles page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/roles_page; devserver."""
    return render_page("roles", ctx=ctx, page="/8021x/roles", view=view,
                       data=data or {"devices": [], "roles": [], "types": [], "permissions": {}}, role=role,
                       unavailable=unavailable)
