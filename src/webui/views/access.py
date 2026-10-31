from webui.views.constants import GRANT_RIGHTS
from webui.views.paged import paged
from webui.views.render_page import render_page


def rights_text(grant):
    """Purpose: A grant's rights in words, one entry per category it gives (manual 1.6.13.4).
    Inputs:  grant — a grant's fields (people, machines, signin, sudo: lists; local_admin: bool).
    Returns: list of str, e.g. ["people: edit, reset", "sign-in: keyboard", "sudo: ALL", "local administrator"].
    Fails:   never.
    Feeds:   access; people (a person's page)."""
    out = [f"{label.lower()}: {', '.join(grant[key])}" for key, label, _ in GRANT_RIGHTS if grant.get(key)]
    if grant.get("sudo"):
        out.append("sudo: " + ", ".join(grant["sudo"]))
    if grant.get("local_admin"):
        out.append("local administrator")
    return out


def access(ctx, view, grants=None, grant=None, query=None, unavailable=""):
    """Purpose: Directory · Access (manual 1.6.13.7): the grants (who, where, what each gives, whom it reaches; search,
             50 a page), a grant's page (its people and machines by name; Change and Remove) and Add grant, from a
             template or empty, each category's rights as switches; every change held for the Access page's Apply
             (1.8.6.5), for groups:admin (the Directory Administrators).
    Inputs:  ctx — page context; view — "list", "grant" or "new"; grants — list_grants' dict (the list; the templates
             on Add grant); grant — show_grant's dict; query — dict: q, page, template (Add grant's start);
             unavailable — why the grants could not be read.
    Returns: HTML str, in the navigation's Access page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/access_page; devserver."""
    rows = [{**g, "gives": rights_text(g), "who_text": " ".join(g.get("who") or []),
             "where_text": " ".join(g.get("where") or [])} for g in (grants or {}).get("grants") or []]
    page = paged(rows, ("name", "kind", "description", "who_text", "where_text"), query or {})
    templates = (grants or {}).get("templates") or {}
    start = templates.get((query or {}).get("template") or "") or {}
    grant = grant or {}
    return render_page("access", ctx=ctx, page="/directory/access", view=view, grants=page["rows"],
                       total=page["total"], at=page["at"], pages=page["pages"], search=page["search"],
                       g=grant, gives=rights_text(grant) if grant else [], rights=GRANT_RIGHTS, templates=templates,
                       template=(query or {}).get("template") if start else "", start=start,
                       unavailable=unavailable)
