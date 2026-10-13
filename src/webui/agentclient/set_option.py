from webui.agentclient.connection import call_agent


def set_option(option, data, where):
    """Purpose: Set a DHCP option for every subnet, a subnet, a class or a reservation.
             Agent route: POST /v1/dhcp/options (dhcp:write), timeout 960 s (an apply may run for minutes, 2.1.2.23).
    Inputs:  option — name or code; data — its value; where — {"subnet"|"class"|"mac": value} or {} (every subnet),
             "always_send" optional.
             No actor: the agent uses the token's user.
    Returns: {"where": label, "option": saved dict, "applied", "output"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: what fabriclib refuses), AuthError (401),
             PermissionDenied (403); a failed apply is applied=False (saved anyway).
    Feeds:   src/webui/routes/kea_post."""
    return call_agent("POST", "/v1/dhcp/options", {"option": option, "data": data, **where}, timeout=960)
