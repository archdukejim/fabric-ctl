from webui.agentclient.connection import call_agent


def ssh_hosts():
    """Purpose: The SSH page's host certificates: the host CA and each machine's certificate state (manual
             1.6.11.9.11).
             Agent route: GET /v1/ssh/hosts (domain:read).
    Inputs:  none.
    Returns: {"on", "public_key", "fingerprint", "machines": [{"name", "ou", "managed", "state", "until",
             "principals", "types"}]}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
    Feeds:   src/webui/routes/get_page (/ssh).
    """
    return call_agent("GET", "/v1/ssh/hosts")
