from webui.agentclient.connection import call_agent


def settings_export():
    """Purpose: the settings file (manual 1.8.5.4): every wizard setting, no secret and nothing console-only. Agent
             route: GET /v1/settings/export (settings:admin).
    Inputs:  none.
    Returns: {"text": the YAML, "name": "<site>-settings.yaml"}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/settings_page (/settings/export).
    """
    return call_agent("GET", "/v1/settings/export")
