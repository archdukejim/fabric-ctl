from fabriclib.common.errors import ValidationError

EMPTY = {"options": [], "option_defs": [], "client_classes": []}


def set_owner(plan, scope):
    """Purpose: the option set a definition or a class change works on: the domain's or the site's (manual
             1.10.4.24.1).
    Inputs:  plan — the site's plan (site_plan: domain_options, site_options); scope — "domain" (or 0.8's "org") or
             "site".
    Returns: {"set" (a copy of the set's lists), "label", "key" ("domain" or the site), "defs" (the definitions in force
             from outside the set: the domain's for a site's set), "write" (function({list name: list}) ->
             write_plan changes)}.
    Fails:   ValidationError: a scope other than domain or site; the domain's set not made yet.
    Feeds:   define_plan_option, undefine_plan_option, add_plan_class, remove_plan_class."""
    scope = "domain" if scope == "org" else scope        # 0.8's word for it (1.10.4.24.5)
    if scope not in ("domain", "site"):
        raise ValidationError("definitions and classes belong to domain or site")
    dom = plan.get("domain_options")
    if scope == "domain" and dom is None:
        raise ValidationError("the domain's DHCP options are not made yet: run an apply at the root site "
                              "(its convergence makes them)")
    chosen = dom if scope == "domain" else (plan.get("site_options") or EMPTY)
    key = "domain" if scope == "domain" else plan["site"]
    copy = {k: [dict(x) for x in chosen.get(k) or []] for k in EMPTY}
    return {"set": copy, "label": "the domain" if scope == "domain" else f"site {plan['site']}", "key": key,
            "defs": [] if scope == "domain" else list((dom or EMPTY).get("option_defs") or []),
            "write": lambda fields: [{"do": "set", "what": "options", "site": plan["site"], "key": key,
                                      "fields": fields}]}
