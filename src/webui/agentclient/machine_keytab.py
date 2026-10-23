from webui.agentclient.connection import call_agent
from webui.agentclient.quote_segment import quote_segment


def machine_keytab(name, service, user, path=""):
    """Purpose: A service's keytab on a computer (manual 1.6.12.9): the one command its administrator pastes into an
             SSH session on it. Nothing is changed and nothing secret is in it, so it is not held for an Apply.
             Agent route: POST /v1/machines/<name>/keytab (machines:admin).
    Inputs:  name — the computer's host name; service — the service class (HTTP, postgres); user — the service's
             local user; path — where the keytab goes ("" for the tool's default).
    Returns: {"machine", "command", "spns"}.
    Fails:   the call_agent exceptions: ValidationError (400: the machine, class, user or path refused, with why),
             AgentError, AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/directory_post (/directory/machines/<name>/keytab).
    """
    body = {"service": service, "user": user, **({"path": path} if path else {})}
    return call_agent("POST", f"/v1/machines/{quote_segment(name)}/keytab", body)
