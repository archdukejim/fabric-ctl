from webui.agentclient.connection import call_agent


def logon_change(op, ou, console=None, remote=None):
    """Purpose: Set or clear the log-on policy of one OU of the site's machines (manual 1.6.11.4), saved and applied.
             Agent routes: POST /v1/domain/logon/set and /v1/domain/logon/clear (gpo:admin).
    Inputs:  op — "set" or "clear"; ou — the OU's path below the site's OU ("site" for the site's OU); console,
             remote — lists of group names for set (None: that right left as it is).
    Returns: dict: {"ou", "applied", "output"} and, for set, "console" and "remote" as saved.
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
             ValidationError for an OU path or group refused, a group not in the domain, or a change that would
             leave the site's machines without a policy.
    Feeds:   src/webui/routes/directory_post (logon).
    """
    body = {"ou": ou}
    if op == "set":
        body.update({k: val for k, val in (("console", console), ("remote", remote)) if val is not None})
    return call_agent("POST", f"/v1/domain/logon/{'set' if op == 'set' else 'clear'}", body)
