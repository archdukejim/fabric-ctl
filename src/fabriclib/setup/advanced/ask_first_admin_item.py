from fabriclib.setup.ask_first_admin import ask_first_admin
from fabriclib.setup.common.ask_setting import ask_setting
from fabriclib.setup.common.first_admin_needed import first_admin_needed
from fabriclib.setup.common.valid_setting import FIRST_ADMIN


def ask_first_admin_item(ctx):
    """Purpose: the menu's first-admin item (manual 1.2.9.11.3): the first admin's user name
             (setup.vars.webui_admin_user) and, when setup creates them, their password (setup.admin_password,
             typed twice, checked against the password policy) — guided mode's questions.
    Inputs:  ctx — SetupContext: vars (webui_admin_user; changed), admin_password (replaced), origins. Interactive.
    Returns: None.
    Fails:   EOFError from input().
    Feeds:   setup/advanced/setup_menu."""
    ctx.vars["webui_admin_user"] = ask_setting("webui_admin_user", ctx.vars.get("webui_admin_user") or FIRST_ADMIN)
    ctx.origins.pop("webui_admin_user", None)
    if first_admin_needed(ctx):
        ctx.admin_password = None
        ask_first_admin(ctx, needed=True)
