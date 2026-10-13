from webui.agentclient.connection import call_agent


def add_client_class(name, test, next_server, boot_file):
    """Purpose: Add a DHCP client class (Kea expression, optional network-boot fields).
             Agent route: POST /v1/dhcp/classes (dhcp:write), timeout 960 s (an apply may run for minutes, 2.1.2.23).
    Inputs:  name, test, next_server, boot_file — str as typed. No actor: the agent uses the token's user.
    Returns: {"class": saved dict, "applied", "output"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: what fabriclib refuses), AuthError (401),
             PermissionDenied (403); a failed apply is applied=False (saved anyway).
    Feeds:   src/webui/routes/kea_post."""
    return call_agent("POST", "/v1/dhcp/classes", {"name": name, "test": test, "next_server": next_server,
                                              "boot_file": boot_file}, timeout=960)
