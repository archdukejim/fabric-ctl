from webui.agentclient.connection import call_agent


def add_subnet(network, name, vlan, router, pools, notes, allow_overlap=""):
    """Purpose: Add a DHCP subnet (name, VLAN record, router, pools, notes); the agent saves and applies it.
             Agent route: POST /v1/dhcp/subnets (dhcp:write), timeout 960 s (an apply may run for minutes, 2.1.2.23).
    Inputs:  network, name, vlan, router, notes, allow_overlap — str as typed; pools — list of "first - last".
             No actor: the agent uses the token's user.
    Returns: {"subnet": saved dict, "applied": bool, "output": last 2000 chars of apply}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: what fabriclib refuses), AuthError (401),
             PermissionDenied (403); a failed apply is applied=False (saved anyway).
    Feeds:   src/webui/routes/kea_post."""
    return call_agent("POST", "/v1/dhcp/subnets", {"network": network, "name": name, "vlan": vlan, "router": router,
                                              "pools": pools, "notes": notes, "allow_overlap": allow_overlap},
                       timeout=960)
