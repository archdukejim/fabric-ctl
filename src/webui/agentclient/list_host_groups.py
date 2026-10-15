from webui.agentclient.connection import call_agent


def list_host_groups():
    """Purpose: The site's host groups with their machines and the sudo rules naming each (manual 1.6.11.7).
             Agent route: GET /v1/host-groups (domain:read).
    Inputs:  none.
    Returns: list of dicts from fabriclib.directory.list_host_groups: name, short, machines, other_members, rules,
             hosts, fabric.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/directory_page (view "machines").
    """
    return call_agent("GET", "/v1/host-groups")
