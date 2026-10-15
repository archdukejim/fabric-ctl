from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def rotate_radius_secret(name, secret=""):
    """Purpose: Give a RADIUS client a new shared secret; saved and applied at once.
             Agent route: POST /v1/radius/clients/<name>/rotate (radius:admin), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  name — client name; secret — str, "" (default) for the agent to generate one.
    Returns: {"secret": str shown once, "applied": bool, "output": str}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for an unknown client.
    Feeds:   src/webui/routes/radius_post (rotate; never passes a secret).
    """
    return call_agent("POST", f"/v1/radius/clients/{quote_segment(name)}/rotate", {"secret": secret}, timeout=960)
