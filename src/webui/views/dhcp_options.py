from webui.views.option_owner import option_owner
from webui.views.render_page import render_page


def dhcp_options(ctx, overview, target=""):
    """Purpose: DHCP · DHCP options (manual 1.10.4.40.1, 1.10.4.24): the domain's and the site's option sets, each
             subnet and reservation with its options and netboot preset; for a target, what a client gets there with
             its sources, and for a subnet or reservation its own options and preset with their forms. Each change
             waits for this page's Apply. The forms show only with dhcp:write.
    Inputs:  ctx — page context; overview — option_sets' dict; target — the target shown ("" the sets).
    Returns: HTML str.
    Fails:   LookupError for a subnet or reservation not there (option_owner); Jinja2 errors propagate.
    Feeds:   src/webui/routes/options_page; the dev preview."""
    return render_page("dhcp_options", ctx=ctx, page="/networks/options", d=overview, target=target,
                       owner=option_owner(overview, target))
