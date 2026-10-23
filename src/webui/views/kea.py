from webui.views.render_page import render_page


def kea(ctx, overview, msg="", err=""):
    """Purpose: The Kea tab: subnets, reservations with add/remove forms, and leases — or how to turn DHCP on.
    Inputs:  ctx — page context; overview — dhcp_overview() dict (enabled, interfaces, lease_time, ddns_zone,
             subnets, leases, leases_error); msg, err — flash texts.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/get_page (/kea); devserver.
    """
    return render_page("kea", ctx=ctx, page="/kea", d=overview, msg=msg, err=err)
