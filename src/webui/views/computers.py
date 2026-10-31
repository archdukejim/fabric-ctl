from webui.views.constants import COMPUTER_SECTIONS, COMPUTER_TYPES
from webui.views.paged import paged
from webui.views.render_page import render_page


def _filtered(machines, query):
    """Purpose: The list's filters (manual 1.6.12.6): by type ("none" for a computer with none) and by site.
    Inputs:  machines — list_machines' rows; query — dict: type, site.
    Returns: (rows kept, each with "sites_text" and "groups_text" for the search; {"type", "site"} as applied: a value
             not among the choices is dropped).
    Fails:   never.
    Feeds:   computers."""
    sites = sorted({s for m in machines for s in m.get("sites") or []})
    kind = query.get("type") if query.get("type") in (*COMPUTER_TYPES, "none") else ""
    site = query.get("site") if query.get("site") in sites else ""
    rows = [{**m, "sites_text": " ".join(m.get("sites") or []), "groups_text": " ".join(m.get("groups") or [])}
            for m in machines
            if (not kind or (m.get("type") or "none") == kind) and (not site or site in (m.get("sites") or []))]
    return rows, {"type": kind, "site": site}, sites


def _gives(rights):
    """Purpose: What a grant gives on a computer, in words: its sign-ins, local administrator, sudo and the machine
             rights over it (manual 1.6.13.4).
    Inputs:  rights — a grant's {signin, local_admin, sudo, machines, people}.
    Returns: list of str.
    Fails:   never.
    Feeds:   computers."""
    out = []
    if rights.get("signin"):
        out.append("sign-in: " + ", ".join(rights["signin"]))
    if rights.get("local_admin"):
        out.append("local administrator")
    if rights.get("sudo"):
        out.append("sudo: " + ", ".join(rights["sudo"]))
    if rights.get("machines"):
        out.append("manage it: " + ", ".join(rights["machines"]))
    return out


def computers(ctx, view, machines=None, computer=None, groups=None, query=None, keytab=None, unavailable=""):
    """Purpose: Directory · Computers (manual 1.6.12.6): the list (search, filters by type and site, 50 a page), a
             computer's page (its facts, the grants that reach it, its machine groups, its 802.1X device; Change type,
             Sites, Move to folder, Disable or Enable, Machine groups, Remove, Add a service), Add computer, the
             Machine groups tab and a service's keytab command; every change held for the page's Apply (1.8.6.5) but
             the keytab command, which changes nothing.
    Inputs:  ctx — page context; view — "list", "computer", "new", "groups" or "keytab"; machines — list_machines'
             rows (the list; the machine groups tab's members form); computer — machine_overview's dict; groups —
             list_host_groups' rows (the machine groups tab); query — dict: q, page, type, site; keytab — the keytab
             answer {"machine", "command", "spns"}; unavailable — why it could not be read.
    Returns: HTML str, in the navigation's Computers page.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/computers_page, directory_post (keytab); devserver."""
    rows, applied, sites = _filtered(machines or [], query or {})
    page = paged(rows, ("name", "type", "os", "folder", "sites_text", "groups_text"), query or {})
    keep = {k: v for k, v in applied.items() if v}
    if computer and computer.get("grants"):
        computer = {**computer, "grants": [{**g, "gives": _gives(g.get("rights") or {})} for g in computer["grants"]]}
    return render_page("computers", ctx=ctx, page="/directory/computers", view=view, sections=COMPUTER_SECTIONS,
                       types=COMPUTER_TYPES, machines=page["rows"], all_machines=machines or [], total=page["total"],
                       at=page["at"], pages=page["pages"], search=page["search"], applied=applied, keep=keep,
                       sites=sites, c=computer or {}, groups=groups or [], keytab=keytab or {},
                       unavailable=unavailable)
