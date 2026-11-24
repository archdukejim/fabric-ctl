from webui.agentclient.connection import call_agent


def backup_overview():
    """Purpose: the Backups page's read (manual 1.3.7.9): the bundles with their checks, the schedule and its runs, the
             sections, whether a backup or restore runs. Agent route: GET /v1/backup (Domain Admins, 1.3.7.12).
    Inputs:  none (the thread's token).
    Returns: {"bundles": [{"file", "kind", "when", "size", "fabric_version", "host", "sections", "error", "check",
             "opened_by", "method"}], "schedule": {"on", "time", "keep", "public_key", "next", "last", "last_result"},
             "running", "site", "version", "sections": [{"name", "what", "depends", "alone"}]}.
    Fails:   the call_agent exceptions: ValidationError (400: not a Domain Admin, the DC not answering), AgentError,
             AuthError, PermissionDenied.
    Feeds:   src/webui/routes/backups_page."""
    return call_agent("GET", "/v1/backup")
