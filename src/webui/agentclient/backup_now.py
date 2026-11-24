from webui.agentclient.connection import call_agent


def backup_now(passphrase=None, scheduled_key=False):
    """Purpose: Back up now (manual 1.3.7.9): an online bundle of all seven sections, as a job. Agent route:
             POST /v1/backup/now (Domain Admins, 1.3.7.12; body: passphrase, or scheduled_key true).
    Inputs:  passphrase — str (12 characters or more) or None; scheduled_key — True: the schedule's public key.
    Returns: str, the job's id (read_job).
    Fails:   the call_agent exceptions: ValidationError (400: not a Domain Admin, a passphrase too short, no schedule's
             key, a backup running), AgentError, AuthError, PermissionDenied; KeyError for a reply with no id.
    Feeds:   src/webui/routes/backups_post."""
    body = {"scheduled_key": True} if scheduled_key else {"passphrase": passphrase or ""}
    return call_agent("POST", "/v1/backup/now", body)["id"]
