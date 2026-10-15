from webui.agentclient.connection import call_agent


def list_sudo_rules():
    """Purpose: The site's sudo rules, each fabric's editor's, the site's default or an admin's own (manual 1.6.11.7).
             Agent route: GET /v1/sudo (domain:read).
    Inputs:  none.
    Returns: list of dicts from fabriclib.directory.list_sudo_rules: name, kind, users, commands, run_as, hosts,
             host_group.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/directory_page (view "machines").
    """
    return call_agent("GET", "/v1/sudo")
