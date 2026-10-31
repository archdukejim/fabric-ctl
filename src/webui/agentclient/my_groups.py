from webui.agentclient.connection import call_agent


def my_groups():
    """Purpose: Groups I manage (manual 1.8.6.6, 2.1.6.67): each group the signed-in person manages, its members and
             its controls (add, remove, only_from). Agent route: GET /v1/account/groups (any sign-in, their own).
    Inputs:  none (the session's token names the person).
    Returns: {"groups": [{"name", "add", "remove", "only_from", "members"}]}.
    Fails:   the call_agent exceptions: ValidationError (400: the DC not running).
    Feeds:   src/webui/routes/get_page (/account/groups).
    """
    return call_agent("GET", "/v1/account/groups")
