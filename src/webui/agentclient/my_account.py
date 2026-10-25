from webui.agentclient.connection import call_agent


def my_account():
    """Purpose: My account (manual 1.8.6.6), read-only: the signed-in person's own details, their groups, the
             certificates fabric issued to them and the 802.1X devices they own. Agent route: GET /v1/account (any
             sign-in, their own: the token's user).
    Inputs:  none (the session's token names the person).
    Returns: {"uid", "person": {field: value}, "groups": [names], "certs": [...], "devices": [...]}.
    Fails:   the call_agent exceptions: ValidationError (400: the DC not running).
    Feeds:   src/webui/routes/get_page (/account).
    """
    return call_agent("GET", "/v1/account")
