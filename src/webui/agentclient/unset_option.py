from webui.agentclient.connection import call_agent


def unset_option(option, where):
    """Purpose: Remove a DHCP option the admin set.
             Agent route: POST /v1/dhcp/options/delete (dhcp:write), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  option — name or code; where — as set_option. No actor: the agent uses the token's user.
    Returns: {"where": label, "applied", "output"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: what fabriclib refuses), AuthError (401),
             PermissionDenied (403); a failed apply is applied=False (saved anyway).
    Feeds:   src/webui/routes/kea_post."""
    return call_agent("POST", "/v1/dhcp/options/delete", {"option": option, **where}, timeout=960)
