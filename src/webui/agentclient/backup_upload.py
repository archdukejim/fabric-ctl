import json

from webui.agentclient import connection
from webui.agentclient.errors import AgentError, AuthError, NotFound, PermissionDenied, ValidationError

TIMEOUT = 300                      # seconds a send or the answer (the bundle's check) may take


def backup_upload(name, pieces):
    """Purpose: an uploaded bundle passed on to fabric-agent as it arrives (manual 1.3.7.9), chunked, never held.
             Agent route: POST /v1/backup/upload (Domain Admins, 1.3.7.12; its name in X-Fabric-Bundle).
    Inputs:  name — the bundle's file name; pieces — iterable of bytes (the form's file part).
    Returns: {"file", "size"}.
    Fails:   ValidationError (400: not a Domain Admin, not a bundle's name, already there, too large, the disk too
             full, not whole), AuthError (401), PermissionDenied (403), NotFound (404), AgentError (the agent down or
             gone mid-upload, another status).
    Feeds:   src/webui/routes/backups_upload."""
    conn = connection._UnixConnection(TIMEOUT)          # looked up at the call: the dev preview replaces it
    token = getattr(connection._local, "token", None)
    headers = {"X-Fabric-Bundle": name, "Content-Type": "application/octet-stream", "Transfer-Encoding": "chunked"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        conn.request("POST", "/v1/backup/upload", body=pieces, headers=headers, encode_chunked=True)
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"null") or {}
    except (OSError, ValueError) as exc:
        raise AgentError(f"fabric-agent did not take the upload: {exc}") from exc
    finally:
        conn.close()
    error = {400: ValidationError, 401: AuthError, 403: PermissionDenied, 404: NotFound}.get(resp.status)
    if error:
        raise error(data.get("error", "refused"))
    if resp.status != 200:
        raise AgentError(f"fabric-agent error {resp.status}: {data.get('error', '')}")
    return data
