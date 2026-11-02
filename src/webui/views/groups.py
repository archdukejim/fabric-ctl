import re

from webui.views.constants import GROUP_KINDS
from webui.views.paged import paged
from webui.views.render_page import render_page


def _serves(name):
    """Purpose: the page of what a computed group serves (1.8.8.3): a grant's two groups its grant's page; a set of
             machines' (access-<n>) the grants' list, since several grants may share a set.
    Inputs:  name — the group's name.
    Returns: (link, label), or ("", "") for a name of neither form.
    Fails:   never.
    Feeds:   groups."""
    m = re.fullmatch(r"grant-(.+)-(who|where)", name)
    if m:
        return f"/directory/access/{m.group(1)}", f"grant {m.group(1)}"
    if re.fullmatch(r"access-\d+(-[a-z-]+)?", name):
        return "/directory/access", "a set of machines' grants"
    return "", ""


def groups(ctx, view, groups=None, group=None, query=None, unavailable=""):
    """Purpose: Directory · Groups (manual 1.6.12.5): the list (kind and member count; search, 50 a page), a group's
             page in its two levels (2.1.6.67: what it grants and its managers; its members) or Create group; every
             change held for the Groups page's Apply (1.8.6.5).
    Inputs:  ctx — page context; view — "list", "group" or "new"; groups — list_groups' dict (the list); group —
             show_group's dict (the group's page); query — dict: q, page, internal ("1" shows fabric's computed
             groups, hidden by default: 1.8.8.3); unavailable — why it could not be read.
    Returns: HTML str, in the navigation's Groups page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/groups_page; devserver."""
    internal = str((query or {}).get("internal") or "") == "1"
    rows = [{**g, "kind_label": GROUP_KINDS.get(g.get("kind"), (g.get("kind") or "", ""))[0]}
            for g in (groups or {}).get("groups") or [] if internal or g.get("kind") != "computed"]
    for r in rows:
        if r.get("kind") == "computed":
            r["serves"], r["serves_label"] = _serves(str(r.get("name") or ""))
    hidden = sum(1 for g in (groups or {}).get("groups") or [] if g.get("kind") == "computed") if not internal else 0
    page = paged(rows, ("name", "kind_label", "description"), query or {})
    group = group or {}
    managers = group.get("managers") or {}
    me = str((ctx or {}).get("user") or "")
    return render_page("groups", ctx=ctx, page="/directory/groups", view=view, groups=page["rows"],
                       total=page["total"], at=page["at"], pages=page["pages"], search=page["search"], g=group,
                       kind=GROUP_KINDS.get(group.get("kind"), (group.get("kind") or "", "")), mgr=managers,
                       manages=me in (managers.get("managers") or []), unavailable=unavailable,
                       internal=internal, hidden=hidden)
