from fabriclib.setup.ask_first_admin import ask_first_admin
from fabriclib.setup.common.ask_admin_fact import ask_admin_fact
from fabriclib.setup.common.first_admin_needed import first_admin_needed
from fabriclib.setup.common.first_admin_refused import KEYS


def ask_first_admin_item(ctx):
    """Purpose: the menu's first-admin item (manual 1.2.9.11.3): the first Directory Administrator's user name, first
             and last names and e-mail address (setup.vars.webui_admin_user, webui_admin_first_name,
             webui_admin_last_name, webui_admin_email; 2.1.6.93) and, when setup creates them, their password
             (setup.admin_password, typed twice, checked against the password policy) —
             guided mode's questions, each fact asked again with its current value offered.
    Inputs:  ctx — SetupContext: vars (the four facts; changed), admin_password (replaced), origins. Interactive.
    Returns: None.
    Fails:   EOFError from input().
    Feeds:   setup/advanced/setup_menu."""
    for key in KEYS:
        ctx.vars[key] = ask_admin_fact(key, ctx.vars.get(key))
        ctx.origins.pop(key, None)
    if first_admin_needed(ctx):
        ctx.admin_password = None
        ask_first_admin(ctx, needed=True, facts_asked=True)
