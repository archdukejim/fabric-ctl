from fabriclib.common.errors import ValidationError

EMPTY = {"options": [], "option_defs": [], "client_classes": []}


def set_owner(plan, scope):
    """Purpose: the option set a definition or a class change works on: the organisation's or the site's (manual
             1.10.4.24.1).
    Inputs:  plan — the site's plan (site_plan: org_options, site_options); scope — "org" or "site".
    Returns: {"set" (a copy of the set's lists), "label", "key" ("org" or the site), "defs" (the definitions in force
             from outside the set: the organisation's for a site's set), "write" (function({list name: list}) ->
             write_plan changes)}.
    Fails:   ValidationError: a scope other than org or site; the organisation's set not in the domain yet.
    Feeds:   define_plan_option, undefine_plan_option, add_plan_class, remove_plan_class."""
    if scope not in ("org", "site"):
        raise ValidationError("definitions and classes belong to org (the organisation) or site")
    org = plan.get("org_options")
    if scope == "org" and org is None:
        raise ValidationError("the organisation's DHCP options are not in the domain yet: run an apply at the top site")
    chosen = org if scope == "org" else (plan.get("site_options") or EMPTY)
    key = "org" if scope == "org" else plan["site"]
    copy = {k: [dict(x) for x in chosen.get(k) or []] for k in EMPTY}
    return {"set": copy, "label": "the organisation" if scope == "org" else f"site {plan['site']}", "key": key,
            "defs": [] if scope == "org" else list((org or EMPTY).get("option_defs") or []),
            "write": lambda fields: [{"do": "set", "what": "options", "site": plan["site"], "key": key,
                                      "fields": fields}]}
