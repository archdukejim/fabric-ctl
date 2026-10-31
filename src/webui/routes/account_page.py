from webui import agentclient as actions
from webui import views


def _factors_url(h):
    """Purpose: Keycloak's page of the person's own sign-in factors (TOTP, passkeys: 1.8.6.6, 2.1.1.62).
    Inputs:  h — the request handler (its app: the sign-in service's origin and realm, from webui.json).
    Returns: the URL, or "" when the app does not know them (the dev preview).
    Fails:   never.
    Feeds:   account_page."""
    origin = getattr(h.app, "sso_origin", "") or ""
    realm = ((getattr(h.app, "cfg", None) or {}).get("keycloak") or {}).get("realm", "")
    return f"{origin}/realms/{realm}/account/account-security/signing-in" if origin and realm else ""


def account_page(h, ctx, path):
    """Purpose: My account (manual 1.8.6.6): /account (the person's own details, password, sign-in factors,
             certificates and devices) or /account/groups (the groups they manage). Every signed-in person sees it.
    Inputs:  h — the request handler (send); ctx — page context; path — "/account" or "/account/groups".
    Returns: the page sent; a read refused by fabric-agent (the DC not running) is said on the page, the password
             form still shown.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   get_page."""
    if path == "/account/groups":
        try:
            groups, error = actions.my_groups().get("groups") or [], ""
        except actions.ValidationError as exc:
            groups, error = [], str(exc)
        return h.send(200, views.account(ctx, groups=groups, page=path, error=error))
    try:
        data, error = actions.my_account(), ""
    except actions.ValidationError as exc:
        data, error = None, str(exc)
    return h.send(200, views.account(ctx, data, factors_url=_factors_url(h), page=path, error=error))
