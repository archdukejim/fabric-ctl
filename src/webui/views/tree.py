from webui.views.paged import paged
from webui.views.render_page import render_page

# where an object's own page is (1.8.8.4: Open keeps the tree's place in its address)
PAGES = {"person": "/directory/people/", "service account": "/directory/people/", "group": "/directory/groups/",
         "machine": "/directory/computers/"}


def tree(ctx, tree=None, query=None, move=None, unavailable=""):
    """Purpose: Directory · Browse (manual 1.8.8.4): the tree down the left (the domain, then each OU on the way to the
             one opened, each child a link that opens it; fabric's fixed OUs marked), the opened OU's contents on the
             right (kind, name linking to its page, state, description; sorted by kind then name; 50 a page), a
             search of the OU or of the whole domain, the switch for the grants' computed groups (1.8.8.3), and Move
             to... for a person, group or computer (1.8.8.5): a form choosing the OU, held for that kind's page's
             Apply (1.8.6.5).
    Inputs:  ctx — page context; tree — browse_ou's dict; query — dict: ou, q, whole, internal, page; move — {"kind",
             "name", "places"} for the Move to... form, or None; unavailable — why the tree could not be read.
    Returns: HTML str, in the navigation's Browse page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/tree_page; devserver."""
    query = query or {}
    tree = tree or {}
    rows = [{**r, "page": PAGES[r["kind"]] + r["name"] if r["kind"] in PAGES else ""}
            for r in tree.get("contents") or []]
    page = paged(rows, ("name", "kind", "description"), {"page": query.get("page")})
    keep = {k: query[k] for k in ("ou", "q", "whole", "internal") if query.get(k)}
    return render_page("tree", ctx=ctx, page="/directory/tree", t=tree, rows=page["rows"], total=page["total"],
                       at=page["at"], pages=page["pages"], ou=str(query.get("ou") or "").strip("/"),
                       q=str(query.get("q") or ""), whole=str(query.get("whole") or "") == "1",
                       internal=str(query.get("internal") or "") == "1", keep=keep, move=move,
                       unavailable=unavailable)
