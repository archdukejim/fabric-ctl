import os


def ca_exists(ctx):
    """Purpose: whether this install already has its CA (its lifetime is then fixed, 2.1.5.6).
    Inputs:  ctx — SetupContext.
    Returns: bool: Step-CA's ca.json exists.
    Fails:   never.
    Feeds:   setup/choose_plan, setup/advanced/ask_ca_lifetime, setup/advanced/menu_items."""
    return os.path.exists(ctx.path("stepca", "data", "config", "ca.json"))
