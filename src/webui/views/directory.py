from webui.views.constants import DIRECTORY_PAGES
from webui.views.render_page import render_page


def directory(ctx, view, data=None, device=None, role=None, msg="", err="", unavailable="", overview=None):
    """Purpose: The Directory's pages and 802.1X's devices and roles (manual 1.8.6.4): devices, one device, roles,
             one role or the Directory's Overview (1.6.12.3) (People, Groups, Computers, Policies: their own views).
    Inputs:  ctx — page context; view — 'devices' | 'device' | 'roles' | 'role' | 'overview';
             data — device_overview() dict (devices, roles, types, permissions), default empty;
             device / role — the item for the detail views; msg, err — flash texts; unavailable — why the directory
             could not be read (shown instead of the data); overview — directory_overview() for the overview view.
    Returns: HTML str, in the navigation's page of the view (DIRECTORY_PAGES).
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/directory_page; devserver.
    """
    return render_page("directory", ctx=ctx, page=DIRECTORY_PAGES.get(view, "/directory"), view=view,
                       data=data or {"devices": [], "roles": [], "types": [], "permissions": {}}, device=device,
                       role=role, msg=msg, err=err, unavailable=unavailable, overview=overview)
