"""The connection to fabric-agent: its socket, the signed-in person's token per thread, and the one request
function every agent call goes through."""
import http.client
import json
import socket
import threading

from webui.agentclient.errors import AgentError, AuthError, NotFound, PermissionDenied, ValidationError

_socket_path = "/agent/agent.sock"
_local = threading.local()          # the signed-in person's ID token for this request's calls


def set_token(token):
    """Purpose: Make every later agent call from this thread carry `token`, which fabric-agent verifies and checks
             permissions against.
    Inputs:  token — str Keycloak ID token of the signed-in person, or None/"" to send no Authorization header.
             Stored in the thread-local `_local`, so each request thread has its own.
    Returns: None.
    Fails:   never — it only sets a thread-local attribute.
    Feeds:   call_agent (reads it); set by src/webui/handler.Handler.handle_request (None first, then the session's
             token)
             and Handler.callback (the fresh login token, for the login audit calls).
    """
    _local.token = token


def configure(path):
    """Purpose: Point this client at fabric-agent's unix socket instead of the default /agent/agent.sock.
    Inputs:  path — str filesystem path of the agent socket; sets the module global `_socket_path`.
    Returns: None.
    Fails:   never — the path is not checked here; a wrong path shows up later as AgentError from _call.
    Feeds:   _UnixConnection.connect; called by src/ux/web/server.py main with cfg["agent_socket"].
    """
    global _socket_path
    _socket_path = path


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, timeout):
        """Purpose: An HTTP connection to fabric-agent that runs over the unix socket instead of TCP.
        Inputs:  timeout — seconds allowed for connecting and for each socket read.
        Returns: None.
        Fails:   never — nothing is opened until connect().
        Feeds:   call_agent (one connection per call).
        Notes:   "fabric-agent" is only the Host header value; no name is resolved.
        """
        super().__init__("fabric-agent", timeout=timeout)

    def connect(self):
        """Purpose: Open the unix stream socket at `_socket_path`; http.client calls it on the first request.
        Inputs:  none (reads self.timeout and the module global `_socket_path`).
        Returns: None; sets self.sock.
        Fails:   OSError (FileNotFoundError, ConnectionRefusedError, PermissionError, socket.timeout) if the socket is
                 missing, the agent is down, or the socket's permissions refuse this uid;
                 call_agent turns it into AgentError.
        Feeds:   http.client.HTTPConnection.request, used by call_agent.
        """
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(_socket_path)


def call_agent(method, path, body=None, timeout=30):
    """Purpose: Send one JSON request to fabric-agent over its unix socket and return the decoded JSON reply.
             Every public function in this module goes through it.
    Inputs:  method — "GET" or "POST"; path — agent path such as "/v1/zones" with names already quoted (quote_segment);
             body — JSON-serialisable object, or None (default) for no body; timeout — seconds, default 30
             (long operations pass more). Sends the thread's token from set_token as Authorization: Bearer.
    Returns: the decoded JSON body of a 200 reply (dict or list; None for an empty body).
    Fails:   AgentError — the socket is missing/refused/timed out (OSError), the reply is not JSON (ValueError),
               or any status other than 200/400/401/403/404 (e.g. 500 agent internal error); NotFound (404: the
               thing named is not there, or an unknown route);
             ValidationError — 400: fabriclib rejected the input; message is the agent's "error", safe to show;
             AuthError — 401: the agent did not accept the ID token (missing, expired, not valid);
             PermissionDenied — 403: the token lacks the permission the route needs
               (fabriclib/rbac/required_permission.py), the route is not in that table, or the peer uid is refused;
             TypeError from json.dumps if `body` is not JSON-serialisable (not wrapped).
    Feeds:   every agent call in src/webui/agentclient/.
    Notes:   src/webui/handler.Handler.handle_request maps these to: 400 page, redirect to /login, 403 page, 503 page.
    """
    conn = _UnixConnection(timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if getattr(_local, "token", None):
            headers["Authorization"] = f"Bearer {_local.token}"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"null")
    except (OSError, ValueError) as exc:
        raise AgentError(f"fabric-agent unavailable: {exc}") from exc
    finally:
        conn.close()
    if resp.status == 400:
        raise ValidationError((data or {}).get("error", "rejected"))
    if resp.status == 404:
        raise NotFound((data or {}).get("error", "not found"))
    if resp.status == 401:
        raise AuthError((data or {}).get("error", "not signed in"))
    if resp.status == 403:
        raise PermissionDenied((data or {}).get("error", "not allowed"))
    if resp.status != 200:
        raise AgentError(f"fabric-agent error {resp.status}: {(data or {}).get('error', '')}")
    return data
