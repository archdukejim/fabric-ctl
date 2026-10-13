from fabriclib.setup.common.dotted_keys import get_dotted, set_dotted
from fabriclib.setup.common.plan_items import PLAN


def apply_plan_defaults(ctx):
    """Purpose: record the effective value of every plan item (the hardened defaults, manual 1.2.9.11.4) and of the DNS
             filter, so what the plan and the menu show is what gets rendered (the template's defaults differ, e.g.
             install_keycloak), and the first admin's question knows whether the web console is on.
    Inputs:  ctx — SetupContext: vars (PLAN keys, dns_filter).
    Returns: None; ctx.vars holds every PLAN key as a bool and dns_filter lower-cased ("bind" unless set).
    Fails:   TypeError/AttributeError from set_dotted when a PLAN key's parent holds a non-dict value.
    Feeds:   setup/run_setup (after collect_vars, before the first admin, the menu and the plan)."""
    for key, default, _, _ in PLAN:
        set_dotted(ctx.vars, key, bool(get_dotted(ctx.vars, key, default)))
    ctx.vars["dns_filter"] = str(ctx.vars.get("dns_filter") or "bind").lower()
