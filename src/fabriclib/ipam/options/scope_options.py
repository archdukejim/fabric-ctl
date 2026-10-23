from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.fields import find_address, find_subnet

SCOPES = ("domain", "site", "subnet", "class", "address")
EMPTY = {"options": [], "option_defs": [], "client_classes": []}


def _set_change(plan, key, fields):
    """Purpose: the write_plan change that replaces lists of an option set.
    Inputs:  plan — the site's plan; key — "domain" or the site's name; fields — {list name: list}.
    Returns: list with one change.
    Fails:   never.
    Feeds:   scope_options."""
    return [{"do": "set", "what": "options", "site": plan["site"], "key": key, "fields": fields}]


def scope_options(plan, scope, target="", domain_class=False):
    """Purpose: the place an option change works on in the address manager (manual 1.10.4.24.5): the domain's
             set, the site's set, a subnet, a client class (the site's, or the domain's with domain_class), or a
             reservation's address; with its current options, the definitions in force there, and how to write a new
             list.
    Inputs:  plan — the site's plan (site_plan: domain_options, site_options, subnets); scope — one of SCOPES (`org`,
             0.8's word, reads as `domain`); target — a subnet's name or network, a class's name, an address;
             domain_class — bool, the class is the domain's.
    Returns: {"label" (for messages and the audit), "options" (the current list, a copy), "defs" (the definitions in
             force there), "domain" (bool: the domain's set is written), "write" (function(new list) -> write_plan
             changes)}.
    Fails:   ValidationError: an unknown scope; a target missing or given where none is taken; the domain's set
             not made yet; no such subnet, class or address; an address that is not a reservation.
    Feeds:   set_plan_option, remove_plan_option."""
    scope = "domain" if scope == "org" else scope        # 0.8's word for it (1.10.4.24.5)
    if scope not in SCOPES:
        raise ValidationError(f"where: one of {', '.join(SCOPES)}")
    if scope in ("domain", "site") and target:
        raise ValidationError(f"{scope} takes no name after it")
    if scope in ("subnet", "class", "address") and not target:
        raise ValidationError(f"{scope}: give its name" + (" (its address)" if scope == "address" else ""))
    dom, mine = plan.get("domain_options"), plan.get("site_options") or EMPTY
    if dom is None and (scope == "domain" or (scope == "class" and domain_class)):
        raise ValidationError("the domain's DHCP options are not made yet: run an apply at the root site "
                              "(its convergence makes them)")
    dom = dom or EMPTY
    in_force = list(dom.get("option_defs") or []) + list(mine.get("option_defs") or [])
    if scope == "domain":
        return {"label": "the domain", "options": list(dom.get("options") or []),
                "defs": list(dom.get("option_defs") or []), "domain": True,
                "write": lambda new: _set_change(plan, "domain", {"options": new})}
    if scope == "site":
        return {"label": f"site {plan['site']}", "options": list(mine.get("options") or []), "defs": in_force,
                "domain": False, "write": lambda new: _set_change(plan, plan["site"], {"options": new})}
    if scope == "class":
        owner = dom if domain_class else mine
        classes = [dict(c) for c in owner.get("client_classes") or []]
        found = next((c for c in classes if c["name"] == target), None)
        if found is None:
            raise ValidationError(f"no client class {target!r} in " + ("the domain's options" if domain_class else
                                                                        f"{plan['site']}'s options"))
        key = "domain" if domain_class else plan["site"]

        def write(new):
            found["options"] = new
            return _set_change(plan, key, {"client_classes": classes})
        return {"label": f"class {target}" + (" (domain)" if domain_class else ""),
                "options": list(found.get("options") or []),
                "defs": list(dom.get("option_defs") or []) if domain_class else in_force, "domain": domain_class,
                "write": write}
    if scope == "subnet":
        sub = find_subnet(plan, target)
        return {"label": f"subnet {sub['name']}", "options": list(sub.get("options") or []), "defs": in_force,
                "domain": False, "write": lambda new: [{"do": "set", "what": "subnet", "site": plan["site"],
                                                     "key": sub["name"], "fields": {"options": new}}]}
    addr, sub = find_address(plan, target)
    if addr["kind"] != "reservation":
        raise ValidationError(f"{addr['ip']} is a {addr['kind']} address: only a reservation is answered by DHCP, so "
                              "only a reservation has options")
    return {"label": f"address {addr['ip']}", "options": list(addr.get("options") or []), "defs": in_force,
            "domain": False, "write": lambda new: [{"do": "set", "what": "address", "site": plan["site"],
                                                 "subnet": sub["name"], "key": addr["ip"],
                                                 "fields": {"options": new}}]}
