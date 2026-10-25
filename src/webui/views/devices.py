from webui.views.render_page import render_page


def devices(ctx, view, data=None, device=None, people=None, unavailable=""):
    """Purpose: 802.1X · Devices (manual 2.1.8.10, 1.8.6.3): the list, Add device, or one device's page (its access,
             certificates, Edit and Remove); every change held for the Devices page's Apply (1.8.6.5).
    Inputs:  ctx — page context; view — "list", "new" or "device"; data — device_overview() (devices, roles, types,
             permissions); device — the device shown; people — user names to choose an owner from (None: typed);
             unavailable — why the devices could not be read.
    Returns: HTML str, in the navigation's Devices page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/devices_page; devserver."""
    return render_page("devices", ctx=ctx, page="/8021x/devices", view=view,
                       data=data or {"devices": [], "roles": [], "types": [], "permissions": {}}, device=device,
                       people=people, unavailable=unavailable)
