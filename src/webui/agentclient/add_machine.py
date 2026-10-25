from webui.agentclient.connection import call_agent


def add_machine(name, kind=None, managed=True):
    """Purpose: Pre-create a machine with a one-time join password, in this site's group.
             Agent route: POST /v1/machines (machines:admin).
    Inputs:  name — the machine's host name; kind — "server", "desktop", "network" or None (its type: its OU and
             group, manual 1.6.13.3);
             managed — False: not managed by fabric (1.6.11.6).
    Returns: str, the one-time join password (shown once, stored nowhere).
    Fails:   the call_agent exceptions: AgentError (down/timeout/other status), ValidationError (400), AuthError (401),
             PermissionDenied (403).
             ValidationError for a bad or taken name.
    Feeds:   src/webui/routes/directory_post (machines/_new -> views.machine_result).
    """
    return call_agent("POST", "/v1/machines", {"name": name, "managed": "yes" if managed else "no",
                                              **({"type": kind} if kind else {})})["password"]
