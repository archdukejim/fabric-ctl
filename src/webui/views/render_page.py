import os

import jinja2

from webui.views.constants import MENU_PERMS
from webui.views.nav_menu import nav_menu

# autoescape; templates in templates/webui-app, no inline scripts or styles (the strict Content-Security-Policy)
_PACKAGE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# templates/ beside the package on a host (lib/webui/templates); a checkout keeps them in templates/webui-app
_TEMPLATES = next((d for d in (os.path.join(_PACKAGE, "templates"),
                               os.path.join(_PACKAGE, "..", "..", "templates", "webui-app")) if os.path.isdir(d)),
                  os.path.join(_PACKAGE, "templates"))
_env = jinja2.Environment(loader=jinja2.FileSystemLoader(_TEMPLATES), autoescape=True, trim_blocks=True,
                          lstrip_blocks=True)


def render_page(name, **kw):
    """Purpose: Render one template in the console's frame (manual 1.8.6.2) with the common page variables, hiding the
             navigation entries, sub-menus and forms the signed-in person has no permission for.
    Inputs:  name — a template in templates/webui-app (without .html); kw — the template's variables: ctx (dict with
             user, csrf, perms, version, and the message of the last action in flash ({"ok": str} or {"err": str},
             manual 1.8.6.3); default None = no frame), page (the navigation page shown, its path; default None),
             menu / sections (lists of (view, label), filtered through MENU_PERMS), msg / err (shown as the page's
             message; the session's flash fills them when not given), and any others.
    Returns: the rendered HTML str. Templates also get can(permission), nav (nav_menu's entries), visible (the
             set of navigation paths the person may open), entries (the ids of the entries they see) and bar (the
             page shown's pending changes for the top bar, 1.8.6.5: {"id", "pending", "running"}, or None).
    Fails:   jinja2.TemplateNotFound for an unknown name; other jinja2 errors propagate (e.g. UndefinedError when the
             template reads an attribute of a value the caller left out).
    Feeds:   every page function in src/webui/views/.
    Notes:   This only hides what the person cannot use; fabric-agent enforces every permission. Autoescape is on and
             pages carry no inline script or style, so they work under the server's strict CSP.
    """
    kw.setdefault("ctx", None)
    kw.setdefault("page", None)
    ctx = kw["ctx"] or {}
    perms = set(ctx.get("perms") or ())

    def can(perm):
        return perm in perms
    kw["can"] = can
    kw["nav"] = nav_menu(perms, kw["page"], ctx.get("pending_counts"))
    kw["visible"] = {p["href"] for e in kw["nav"] for p in e["pages"]}
    kw["entries"] = {e["id"] for e in kw["nav"]}
    bar = (ctx.get("pending") or {}).get(kw["page"])
    kw["bar"] = bar if bar and (bar.get("pending") or bar.get("running")) else None
    flash = ctx.get("flash") or {}
    if not kw.get("msg"):
        kw["msg"] = flash.get("ok", "")
    if not kw.get("err"):
        kw["err"] = flash.get("err", "")
    for key in ("menu", "sections"):
        if kw.get(key):
            kw[key] = [(v, label) for v, label in kw[key] if can(MENU_PERMS.get(v, "")) or v not in MENU_PERMS]
    return _env.get_template(f"{name}.html").render(**kw)
