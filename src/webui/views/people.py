from webui.views.constants import PEOPLE_PER_PAGE, PERSON_FIELDS
from webui.views.render_page import render_page


def _matches(user, words):
    """Purpose: Whether a person's row holds every word of a search, in any of the list's columns.
    Inputs:  user — a list_people row; words — lower-case words.
    Returns: bool.
    Fails:   never.
    Feeds:   people."""
    text = " ".join(str(user.get(k) or "") for k in ("uid", "name", "mail", "state", "last_logon")).lower()
    return all(w in text for w in words)


def people(ctx, view, people=None, person=None, query=None, unavailable=""):
    """Purpose: Directory · People (manual 1.6.12.4): the list (search by any column, 50 a page), a person's page
             (their facts, groups, certificates, devices; Edit, Reset password, Unlock, Disable or Enable, Groups,
             Remove) or Add person; every action held for People's Apply (1.8.6.5).
    Inputs:  ctx — page context; view — "list", "person" or "new"; people — list_people's dict (the list; on a
             person's page the groups they may be added to); person — person_overview's dict (the person's page);
             query — dict: q (the search), page (1-based); unavailable — why the directory could not be read.
    Returns: HTML str, in the navigation's People page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/people_page; devserver."""
    query = query or {}
    words = str(query.get("q") or "").lower().split()
    users = [u for u in (people or {}).get("users") or [] if _matches(u, words)]
    pages = max(1, -(-len(users) // PEOPLE_PER_PAGE))
    try:
        at = min(max(1, int(query.get("page") or 1)), pages)
    except ValueError:
        at = 1
    shown = users[(at - 1) * PEOPLE_PER_PAGE:at * PEOPLE_PER_PAGE]
    details = person_groups = []
    if person:
        values = person.get("person") or {}
        details = [(label, values.get(key) or None) for key, label in PERSON_FIELDS]
        mine = set(person.get("groups") or [])
        person_groups = [g["name"] for g in (people or {}).get("groups") or [] if g.get("name") not in mine]
    return render_page("people", ctx=ctx, page="/directory/people", view=view, people=people or {}, users=shown,
                       total=len(users), at=at, pages=pages, search=" ".join(words), person=person or {},
                       details=details, addable=person_groups, fields=PERSON_FIELDS, unavailable=unavailable)
