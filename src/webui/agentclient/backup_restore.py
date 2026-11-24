from webui.agentclient.connection import call_agent


def backup_restore(file, section, key, confirm):
    """Purpose: one section of a bundle restored on this install (manual 1.3.7.8, 1.3.7.9), as a job: a safety bundle
             of it first. Agent route: POST /v1/backup/restore (Domain Admins, 1.3.7.12).
    Inputs:  file — the bundle's file name; section — its name; key — the bundle's passphrase or the schedule's
             private key; confirm — the site's name, typed.
    Returns: str, the job's id (read_job).
    Fails:   the call_agent exceptions: ValidationError (400: not a Domain Admin, the name not typed, secrets alone, a
             backup running, no key), NotFound (no such bundle), AgentError, AuthError, PermissionDenied.
    Feeds:   src/webui/routes/backups_post."""
    return call_agent("POST", "/v1/backup/restore", {"file": file, "section": section, "key": key,
                                                     "confirm": confirm})["id"]
