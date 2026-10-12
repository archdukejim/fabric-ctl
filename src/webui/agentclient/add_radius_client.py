from webui.agentclient.connection import call_agent


def add_radius_client(name, address, message_authenticator=True, secret=""):
    """Purpose: Add a RADIUS client (switch or access point); saved and applied at once.
             Agent route: POST /v1/radius/clients (radius:admin), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  name — client name; address — IP/network; message_authenticator — bool, default True; secret — str,
             "" (default) for the agent to generate one.
    Returns: {"secret": str shown once, "applied": bool, "output": str last 2000 chars of apply}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for bad or duplicate values; a failed apply is applied=False.
    Feeds:   src/webui/routes/radius_post (add -> views.radius_secret).
    """
    return call_agent("POST", "/v1/radius/clients", {"name": name, "address": address, "secret": secret,
                                                "message_authenticator": message_authenticator}, timeout=960)
