from webui.agentclient.connection import call_agent


def backup_reinstall(file, key, confirm):
    """Purpose: the whole bundle restored in place of this install (manual 1.3.7.9): fabric-agent checks it, then
             starts the unit fabric-console-restore, which removes fabric (this console with it) and sets it up from
             the bundle. Agent route: POST /v1/backup/reinstall (Domain Admins, 1.3.7.12).
    Inputs:  file — the bundle's file name; key — its passphrase or the schedule's private key; confirm — the site's
             name, typed.
    Returns: {"started", "unit"} once the unit has started.
    Fails:   the call_agent exceptions: ValidationError (400: not a Domain Admin, the name not typed, a bundle that
             cannot be restored here and why, a wrong key, a backup or restore running), NotFound, AgentError,
             AuthError, PermissionDenied.
    Feeds:   src/webui/routes/backups_post."""
    return call_agent("POST", "/v1/backup/reinstall", {"file": file, "key": key, "confirm": confirm}, timeout=120)
