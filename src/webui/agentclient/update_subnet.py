from webui.agentclient.connection import call_agent


def update_subnet(subnet, fields):
    """Purpose: Change a DHCP subnet's name, VLAN, router, notes or pools; the agent saves and applies it.
             Agent route: POST /v1/dhcp/subnets/update (dhcp:write), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  subnet — its name or network; fields — dict of the fields to change (name, vlan, router, notes: "" clears;
             add_pools, remove_pools: lists).
             No actor: the agent uses the token's user.
    Returns: {"subnet": saved dict, "applied", "output"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: what fabriclib refuses), AuthError (401),
             PermissionDenied (403); a failed apply is applied=False (saved anyway).
    Feeds:   src/webui/routes/kea_post."""
    return call_agent("POST", "/v1/dhcp/subnets/update", {"subnet": subnet, **fields}, timeout=960)
