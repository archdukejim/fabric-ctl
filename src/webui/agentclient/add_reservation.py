from webui.agentclient.connection import call_agent


def add_reservation(mac, ip, hostname):
    """Purpose: Reserve an IP for a MAC; the agent saves it and applies at once (Kea reloads with it).
             Agent route: POST /v1/dhcp/reservations (dhcp:write), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  mac, ip, hostname — str as typed; validated by fabriclib. No actor: the agent uses the token's user.
    Returns: {"reservation": saved dict with "mac" and "ip", "applied": bool, "output": last 2000 chars of apply}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for bad values; a failed apply is applied=False (saved anyway).
    Feeds:   src/webui/routes/post_action for /kea/reservations.
    """
    return call_agent("POST", "/v1/dhcp/reservations", {"mac": mac, "ip": ip, "hostname": hostname}, timeout=960)
