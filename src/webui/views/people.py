from webui.views.access import rights_text
from webui.views.constants import PERSON_FIELDS
from webui.views.paged import paged
from webui.views.render_page import render_page


def people(ctx, view, people=None, person=None, query=None, unavailable="", grants=None):
    """Purpose: Directory · People (manual 1.6.12.4): the list (search by any column, 50 a page), a person's page
             (their facts, groups, certificates, devices; Edit, Reset password, Unlock, Disable or Enable, Groups,
             Remove) or Add person; every action held for People's Apply (1.8.6.5).
    Inputs:  ctx — page context; view — "list", "person" or "new"; people — list_people's dict (the list; on a
             person's page the groups they may be added to); person — person_overview's dict (the person's page);
             query — dict: q (the search), page (1-based); unavailable — why the directory could not be read;
             grants — explain_grants' dict with "error" (the person's page: the grants reaching them; None: not
             shown).
    Returns: HTML str, in the navigation's People page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/people_page; devserver."""
    page = paged((people or {}).get("users") or [], ("uid", "name", "mail", "state", "last_logon"), query or {})
    details = person_groups = []
    if person:
        values = person.get("person") or {}
        details = [(label, values.get(key) or None) for key, label in PERSON_FIELDS]
        mine = set(person.get("groups") or [])
        person_groups = [g["name"] for g in (people or {}).get("groups") or [] if g.get("name") not in mine]
    return render_page("people", ctx=ctx, page="/directory/people", view=view, people=people or {},
                       users=page["rows"], total=page["total"], at=page["at"], pages=page["pages"],
                       search=page["search"], person=person or {}, details=details, addable=person_groups,
                       fields=PERSON_FIELDS, unavailable=unavailable,
                       grants=None if grants is None else {
                           **grants, "grants": [{**g, "gives": rights_text(g.get("rights") or {})}
                                                for g in grants.get("grants") or [] if g.get("reaches")]})
