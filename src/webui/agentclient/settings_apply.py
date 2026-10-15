from webui.agentclient.connection import call_agent


def settings_apply(plan_id):
    """Purpose: apply a plan (manual 1.8.5.5): one apply job, or the plan made again when someone applied first. Agent
             route: POST /v1/settings/apply (settings:admin).
    Inputs:  plan_id — the plan's id (str).
    Returns: {"id"} of the job (read it with read_job), or {"stale": True, "plan": the plan made again}.
    Fails:   the call_agent exceptions: AgentError, ValidationError (400: no such plan — expired, applied, another
             person's), AuthError (401), PermissionDenied (403).
    Feeds:   src/webui/routes/settings_post (/settings/apply).
    """
    return call_agent("POST", "/v1/settings/apply", {"plan": plan_id}, timeout=60)
