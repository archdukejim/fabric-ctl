from webui.views.constants import GROUP_KINDS
from webui.views.paged import paged
from webui.views.render_page import render_page


def groups(ctx, view, groups=None, group=None, query=None, unavailable=""):
    """Purpose: Directory · Groups (manual 1.6.12.5): the list (kind and member count; search, 50 a page), a group's
             page in its two levels (2.1.6.67: what it grants and its managers; its members) or Create group; every
             change held for the Groups page's Apply (1.8.6.5).
    Inputs:  ctx — page context; view — "list", "group" or "new"; groups — list_groups' dict (the list); group —
             show_group's dict (the group's page); query — dict: q, page; unavailable — why it could not be read.
    Returns: HTML str, in the navigation's Groups page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/groups_page; devserver."""
    rows = [{**g, "kind_label": GROUP_KINDS.get(g.get("kind"), (g.get("kind") or "", ""))[0]}
            for g in (groups or {}).get("groups") or []]
    page = paged(rows, ("name", "kind_label", "description"), query or {})
    group = group or {}
    managers = group.get("managers") or {}
    me = str((ctx or {}).get("user") or "")
    return render_page("groups", ctx=ctx, page="/directory/groups", view=view, groups=page["rows"],
                       total=page["total"], at=page["at"], pages=page["pages"], search=page["search"], g=group,
                       kind=GROUP_KINDS.get(group.get("kind"), (group.get("kind") or "", "")), mgr=managers,
                       manages=me in (managers.get("managers") or []), unavailable=unavailable)
