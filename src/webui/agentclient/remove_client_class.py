from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def remove_client_class(name):
    """Purpose: Remove a DHCP client class and its options.
             Agent route: POST /v1/dhcp/classes/<name>/delete (dhcp:write), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  name — the class. No actor: the agent uses the token's user.
    Returns: {"applied", "output"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: what fabriclib refuses), AuthError (401),
             PermissionDenied (403); a failed apply is applied=False (saved anyway).
    Feeds:   src/webui/routes/kea_post."""
    return call_agent("POST", f"/v1/dhcp/classes/{quote_segment(name)}/delete", {}, timeout=960)
