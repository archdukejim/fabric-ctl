from webui.agentclient.connection import call_agent


def coa_session(action, client, session):
    """Purpose: Disconnect a session, or make it authenticate again (reauthenticate; bounce: and re-DHCP on its new
             VLAN), by CoA to its switch; sent at once, nothing applied.
             Agent routes: POST /v1/radius/sessions/disconnect | /v1/radius/sessions/reauthenticate (radius:coa),
             timeout 30 s (three tries of three seconds).
    Inputs:  action — "disconnect", "reauthenticate" or "bounce"; client — the RADIUS client's name; session — its
             Acct-Session-Id.
    Returns: {"action", "client", "session", "mac", "who", "nas_ip", "port", "label", "message"} once acknowledged.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400: refused with why,
             e.g. a vendor without CoA, a closed session, the switch's NAK or no answer), AuthError (401),
             PermissionDenied (403: no radius:coa).
    Feeds:   src/webui/routes/radius_post (sessions).
    """
    route = "disconnect" if action == "disconnect" else "reauthenticate"
    return call_agent("POST", f"/v1/radius/sessions/{route}",
                      {"client": client, "session": session, "bounce": action == "bounce"}, timeout=30)
