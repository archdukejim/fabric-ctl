from webui.views.render_page import render_page


def sites(ctx, overview=None, name="", unavailable=""):
    """Purpose: Directory · Sites (manual 1.6.12.8): each site with its people and machines (counts, linked), its DCs
             and the grants scoped to it; the domain's DCs as counts and this DC's replication; or one site's page
             (its members, linked to its group's page where they are changed, as any group's, 2.1.6.67; its AD site
             read-only: fabric writes AD's sites, subnets and site links).
    Inputs:  ctx — page context; overview — site_overview's dict; name — the site shown ("" for the list);
             unavailable — why the sites could not be read.
    Returns: HTML str, in the navigation's Sites page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/sites_page; devserver."""
    overview = overview or {}
    site = next((s for s in overview.get("sites") or [] if s["name"] == name), None) if name else None
    return render_page("sites", ctx=ctx, page="/directory/sites", o=overview, site_name=name, site=site,
                       unavailable=unavailable or overview.get("error", ""))
