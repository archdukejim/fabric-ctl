from webui.agentclient.connection import call_agent


def map_radius_group(group, vlan="", priority=""):
    """Purpose: Let members of a directory group join the network by password; saved and applied at once.
             Agent route: POST /v1/radius/people (radius:admin), timeout 960 s (an apply may run for minutes, 2.1.2.23).
    Inputs:  group — group name; vlan — str VLAN, "" for none; priority — str, "" for the agent's default 100.
    Returns: {"mapping": {"group", "vlan", ...}, "applied": bool, "output": str}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for an unknown group or bad VLAN/priority.
    Feeds:   src/webui/routes/post_action for /freeradius/people.
    """
    return call_agent("POST", "/v1/radius/people", {"group": group, "vlan": vlan, "priority": priority}, timeout=960)
