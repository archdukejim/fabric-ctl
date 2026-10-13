from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def unmap_radius_group(group):
    """Purpose: Stop a group's members joining by password; saved and applied at once.
             Agent route: POST /v1/radius/people/<group>/delete (radius:admin), timeout 960 s
             (an apply may run for minutes, 2.1.2.23).
    Inputs:  group — group name (quoted).
    Returns: {"applied": bool, "output": str}.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403);
             ValidationError for a group that is not mapped.
    Feeds:   src/webui/routes/post_action for /freeradius/people/<group>/delete.
    """
    return call_agent("POST", f"/v1/radius/people/{quote_segment(group)}/delete", {}, timeout=960)
