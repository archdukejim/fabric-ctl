from webui.agentclient.connection import call_agent


def list_machines():
    """Purpose: The domain's computers (manual 1.6.12.6, the list): each with its type, sites, OS, folder, machine
             groups, state and last sign-in.
             Agent route: GET /v1/machines (domain:read).
    Inputs:  none.
    Returns: list of dicts from fabriclib.directory.list_machines: name, dns, os, type, sites, groups, folder, enabled,
             last_logon, created, dn.
    Fails:   the call_agent exceptions: ValidationError (400: the DC not running), AgentError, AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/computers_page (/directory/computers).
    """
    return call_agent("GET", "/v1/machines")
