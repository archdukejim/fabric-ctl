from webui.agentclient.connection import call_agent


def backup_schedule(time="", keep="", public_key="", off=False):
    """Purpose: the backup schedule (manual 1.3.7.5, 1.3.7.9): its time, how many scheduled bundles are kept and its
             public key, or off. Agent route: POST /v1/backup/schedule (Domain Admins, 1.3.7.12).
    Inputs:  time — "HH:MM" or ""; keep — str of a number or ""; public_key — "age1…" or "" (each "" unchanged);
             off — True: the schedule off.
    Returns: {"schedule": "on HH:MM" | "off", "time", "keep", "public_key"}.
    Fails:   the call_agent exceptions: ValidationError (400: not a Domain Admin, a time or count or key refused, on
             with no key), AgentError, AuthError, PermissionDenied.
    Feeds:   src/webui/routes/backups_post."""
    body = {"off": True} if off else {"time": time, "keep": keep, "public_key": public_key}
    return call_agent("POST", "/v1/backup/schedule", body)
