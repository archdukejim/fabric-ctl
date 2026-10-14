import os

import jinja2

from webui.views.constants import MENU_PERMS, TAB_PERMS, TABS

# autoescape; templates in templates/webui-app, no inline scripts or styles (the strict Content-Security-Policy)
_PACKAGE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# templates/ beside the package on a host (lib/webui/templates); a checkout keeps them in templates/webui-app
_TEMPLATES = next((d for d in (os.path.join(_PACKAGE, "templates"),
                               os.path.join(_PACKAGE, "..", "..", "templates", "webui-app")) if os.path.isdir(d)),
                  os.path.join(_PACKAGE, "templates"))
_env = jinja2.Environment(loader=jinja2.FileSystemLoader(_TEMPLATES), autoescape=True, trim_blocks=True,
                          lstrip_blocks=True)


def render_page(name, **kw):
    """Purpose: Render one template with the common page variables, hiding the tabs, sub-menus and forms the signed-in
             person has no permission for ("*" in TAB_PERMS: any signed-in person).
    Inputs:  name — a template in templates/webui-app (without .html); kw — the template's variables: ctx (dict with
             user, csrf, perms, version;
             default None = no header, tabs or footer), tab (active tab id; default None), menu / sections (lists of
             (view, label), filtered through MENU_PERMS), and any others.
    Returns: the rendered HTML str. Templates also get can(permission) and tabs (TABS filtered through TAB_PERMS).
    Fails:   jinja2.TemplateNotFound for an unknown name; other jinja2 errors propagate (e.g. UndefinedError when the
             template reads an attribute of a value the caller left out).
    Feeds:   every page function in src/webui/views/.
    Notes:   This only hides what the person cannot use; fabric-agent enforces every permission. Autoescape is on and
             pages carry no inline script or style, so they work under the server's strict CSP.
    """
    kw.setdefault("ctx", None)
    kw.setdefault("tab", None)
    perms = set((kw["ctx"] or {}).get("perms") or ())

    def can(perm):          # "*": any signed-in person; a site helpdesk form counts for its permission (2.1.9.21)
        return perm in perms or f"site:{perm}" in perms or (perm == "*" and bool(kw["ctx"]))
    kw["can"] = can
    kw["tabs"] = [t for t in TABS if any(can(q) for q in TAB_PERMS.get(t[0], ()))]
    for key in ("menu", "sections"):
        if kw.get(key):
            kw[key] = [(v, label) for v, label in kw[key] if can(MENU_PERMS.get(v, "")) or v not in MENU_PERMS]
    return _env.get_template(f"{name}.html").render(**kw)
