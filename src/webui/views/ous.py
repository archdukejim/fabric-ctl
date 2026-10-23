from webui.views.constants import OU_ROOTS
from webui.views.render_page import render_page


def ous(ctx, tree=None, path="", unavailable=""):
    """Purpose: Directory · OUs (manual 1.6.12.7): the tree of the domain's folders (fabric's fixed ones marked, the
             admin's own under them, what each holds) with Create OU, or one OU's page (what it holds; Rename and
             Delete on an admin's own); every change held for the OUs page's Apply (1.8.6.5). OUs grant nothing
             (2.1.6.72).
    Inputs:  ctx — page context; tree — list_ous' dict; path — the OU shown ("" for the tree); unavailable — why the
             tree could not be read.
    Returns: HTML str, in the navigation's OUs page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/ous_page; devserver."""
    rows = [{**o, "parent": o["path"].rpartition("/")[0], "leaf": o["path"].rpartition("/")[2]}
            for o in (tree or {}).get("ous") or []]
    parents = [o["path"] for o in rows if o.get("own") or o["path"] in OU_ROOTS]
    ou = next((o for o in rows if o["path"] == path), None) if path else None
    return render_page("ous", ctx=ctx, page="/directory/ous", rows=rows, parents=parents, path=path, ou=ou,
                       unavailable=unavailable)
