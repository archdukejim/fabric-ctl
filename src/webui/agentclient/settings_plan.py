from webui.agentclient.connection import call_agent


def settings_plan(form=None, file=None):
    """Purpose: the plan for a change of the wizard's settings (manual 1.8.5.5), from the wizard's fields or a settings
             file; nothing changes yet. Agent route: POST /v1/settings/plan (settings:admin).
    Inputs:  form — {field: text}, the wizard's fields; file — a settings file's text (one of the two).
    Returns: the plan: {"id", "changes": [{"key", "old", "new"}], "parts", "memory", "ignored": [{"key", "reason"}],
             "source", ...}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: not a settings file, an invalid wizard value,
             named with why — nothing changed), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/settings_post (/settings/plan, /settings/import).
    """
    body = {"form": form} if file is None else {"file": file}
    return call_agent("POST", "/v1/settings/plan", body, timeout=60)
