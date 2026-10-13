from webui.agentclient.connection import call_agent


def remove_subnet(subnet, force):
    """Purpose: Remove a DHCP subnet; refused with active leases unless force.
             Agent route: POST /v1/dhcp/subnets/delete (dhcp:write), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  subnet — its name or network; force — bool. No actor: the agent uses the token's user.
    Returns: {"removed": network, "applied", "output"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: what fabriclib refuses), AuthError (401),
             PermissionDenied (403); a failed apply is applied=False (saved anyway).
    Feeds:   src/webui/routes/kea_post."""
    return call_agent("POST", "/v1/dhcp/subnets/delete", {"subnet": subnet, "force": bool(force)}, timeout=960)
