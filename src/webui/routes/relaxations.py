from webui import agentclient as actions


def relaxations(ctx):
    """Purpose: The security relaxations that are on, for the Settings pages' card (decision 2.1.8.20, global Rule 10).
             Agent route: GET /v1/relaxed-settings (status:read).
    Inputs:  ctx — page context (perms).
    Returns: list of {"setting", "effect"}; [] without status:read; None when they could not be read (the card then
             says so, never "none").
    Fails:   AuthError propagates.
    Feeds:   settings_page, settings_post, get_page (/settings/sign-in)."""
    if "status:read" not in ctx["perms"]:
        return []
    try:
        return actions.relaxed_settings()
    except (actions.AgentError, actions.ValidationError, actions.PermissionDenied):
        return None
