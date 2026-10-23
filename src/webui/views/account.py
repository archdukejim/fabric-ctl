from webui.views.render_page import render_page

# a person's details as My account shows them (2.1.6.93's fields), in order, with their labels
DETAILS = (("first", "First name"), ("last", "Last name"), ("name", "Display name"), ("email", "E-mail"),
           ("phone", "Phone"), ("mobile", "Mobile"), ("title", "Title"), ("department", "Department"),
           ("company", "Company"), ("office", "Office"), ("city", "City"), ("state", "State"), ("country", "Country"),
           ("manager", "Manager"), ("employee_id", "Employee ID"))


def account(ctx, data=None, groups=None, factors_url="", page="/account", error=""):
    """Purpose: My account (manual 1.8.6.6): on /account the person's own details (read-only: the helpdesk changes
             them), their password changed at once, a link to their sign-in factors (Keycloak's own pages), the
             certificates fabric issued to them and their 802.1X devices; on /account/groups the groups they manage,
             with adding and removing members as each group's controls allow (held for My account's Apply).
    Inputs:  ctx — page context; data — my_account's dict (None on /account/groups, or when it could not be read);
             groups — my_groups' list (on /account/groups); factors_url — Keycloak's sign-in page of the person's
             account ("" when unknown: the dev preview); page — "/account" or "/account/groups"; error — why the
             account could not be read ("" when it was).
    Returns: HTML str.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/get_page (/account, /account/groups)."""
    person = (data or {}).get("person") or {}
    details = [(label, person.get(key)) for key, label in DETAILS if person.get(key)]
    return render_page("account", ctx=ctx, page=page, d=data or {}, details=details, groups=groups,
                       factors_url=factors_url, error=error)
