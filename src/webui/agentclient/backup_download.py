import json

from webui.agentclient import connection
from webui.agentclient.errors import AgentError, AuthError, NotFound, PermissionDenied, ValidationError
from webui.agentclient.quote_segment import quote_segment

TIMEOUT = 120                      # seconds a read of the next MiB may take


def backup_download(name):
    """Purpose: a bundle's file, opened as a stream to pass on to the browser (manual 1.3.7.9): never read whole into
             memory. Agent route: GET /v1/backup/bundles/<file> (Domain Admins, 1.3.7.12; audited there).
    Inputs:  name — the bundle's file name.
    Returns: (the response to read from, its length in bytes); the caller closes it.
    Fails:   NotFound (404), ValidationError (400: not a Domain Admin, not a bundle's name), AuthError (401),
             PermissionDenied (403), AgentError (the agent down, another status).
    Feeds:   src/webui/routes/backups_page."""
    conn = connection._UnixConnection(TIMEOUT)          # looked up at the call: the dev preview replaces it
    token = getattr(connection._local, "token", None)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        conn.request("GET", f"/v1/backup/bundles/{quote_segment(name)}", headers=headers)
        resp = conn.getresponse()
    except OSError as exc:
        conn.close()
        raise AgentError(f"fabric-agent unavailable: {exc}") from exc
    if resp.status == 200:
        return resp, int(resp.getheader("Content-Length") or 0)
    text = resp.read().decode(errors="replace")
    conn.close()
    error = {404: NotFound, 400: ValidationError, 401: AuthError, 403: PermissionDenied}.get(resp.status)
    if error:
        try:
            text = json.loads(text).get("error", text)
        except ValueError:
            pass
        raise error(text)
    raise AgentError(f"fabric-agent answered {resp.status}")
