import json
import re
import socket
import struct
import sys
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler

from agent.get_route import get_route
from agent.post_route import post_route
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.keycloak.verify_user_token import verify_user_token
from fabriclib.rbac.required_permission import required_permission
from fabriclib.rbac.user_permissions import user_permissions

MAX_BODY = 64 * 1024
ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")


class Handler(BaseHTTPRequestHandler):
    """One fabric-agent request: peer check (SO_PEERCRED), token and permission check, then the route modules
    (get_route, post_route) — errors become JSON replies."""
    server_version = "fabric-agent"
    sys_version = ""
    allowed_uids = {0}

    def address_string(self):
        """Purpose: the client name used in request log lines (a unix socket peer has no address).
        Inputs:  none.
        Returns: str, always "fabric-web".
        Fails:   never.
        Feeds:   BaseHTTPRequestHandler's logging (log_request / log_error)."""
        return "fabric-web"

    def log_message(self, fmt, *args):
        """Purpose: write one request log line to stderr (the systemd journal of fabric-agent).
        Inputs:  fmt — %-format string; args — its values (from BaseHTTPRequestHandler).
        Returns: None.
        Fails:   never in practice.
        Feeds:   BaseHTTPRequestHandler (every request and error)."""
        sys.stderr.write(f"{fmt % args}\n")

    def reply(self, status, obj):
        """Purpose: send a complete JSON response.
        Inputs:  status — int HTTP status; obj — any JSON-serialisable object.
        Returns: None; status line, Content-Type application/json, Content-Length and the body are written.
        Fails:   TypeError if obj is not JSON-serialisable (inside dispatch it becomes a 500); OSError (BrokenPipeError)
                 if the peer has gone.
        Feeds:   dispatch (every answer)."""
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def peer_uid(self):
        """Purpose: the uid of the process on the other end of the unix socket (SO_PEERCRED; kernel-supplied, cannot be
                 forged by the peer).
        Inputs:  none; reads self.connection.
        Returns: int uid.
        Fails:   OSError if the socket option cannot be read (not a unix socket).
        Feeds:   dispatch (allowed_uids check), authorize (root peers skip the token)."""
        creds = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", creds)[1]

    def authorize(self, method, route):
        """Purpose: decide whether this request may run: root peers always; everyone else needs a valid Keycloak ID
                 token that grants the permission the route requires.
        Inputs:  method — "GET" or "POST"; route — list of path segments after /v1/. Reads the "Authorization: Bearer
                 <token>" header and vars (load_vars) for token verification.
        Returns: None when allowed, with self.user = the token's preferred_username, self.perms = its permission set
                 and self.session = its `sid` (all None for a root peer); otherwise (status, error): (401, reason) when
                 verify_user_token rejects
                 the token or it is missing; (403, "not allowed") when required_permission lists no permission for the
                 route (default deny); (403, "you need the permission <p>") when the token lacks it ("session" needs
                 none).
        Fails:   exceptions other than ValidationError (e.g. KeyError on a token without preferred_username, OSError
                 from load_vars) propagate to dispatch, which answers 500.
        Feeds:   dispatch; self.user feeds actor (and the caller fabric-agent's checks name), self.perms the routes that
                 need a second permission, self.session a person's own password change."""
        self.user, self.perms, self.session = None, None, None
        if self.peer_uid() == 0:
            return None
        auth = self.headers.get("Authorization", "")
        try:
            claims = verify_user_token(load_vars(), auth[7:] if auth.startswith("Bearer ") else "")
        except ValidationError as exc:
            return 401, str(exc)
        need = required_permission(method, route)
        if need is None:
            return 403, "not allowed"
        if need != "session" and need not in user_permissions(claims):
            return 403, f"you need the permission {need}"
        self.user, self.perms = claims["preferred_username"], user_permissions(claims)
        self.session = claims.get("sid")
        return None

    def body(self):
        """Purpose: read and parse the request's JSON body.
        Inputs:  none; reads the Content-Length header and self.rfile. An empty body counts as {}.
        Returns: dict, the parsed object.
        Fails:   ValidationError("request too large") over MAX_BODY (64 KiB), ValidationError("expected a JSON object")
                 for any other JSON value (both -> 400 in dispatch); ValueError / json.JSONDecodeError for a bad
                 Content-Length or invalid JSON (-> 400 "malformed request").
        Feeds:   dispatch (every POST)."""
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY or length < 0:
            raise ValidationError("request too large")
        data = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data, dict):
            raise ValidationError("expected a JSON object")
        return data

    def actor(self, data):
        """Purpose: the user name recorded in the audit log for this change.
        Inputs:  data — the request body; its "actor" is used only for root peers (no token).
        Returns: str — the verified token's user when there is one, else data["actor"].
        Fails:   ValidationError("invalid actor") (-> 400) when a root peer's actor is missing or does not match
                 ACTOR_RE (1-64 characters of letters, digits, . _ @ -, starting with a letter or digit).
        Feeds:   dispatch -> post_route and every fabriclib change operation."""
        if self.user:                       # the verified token's user, not what the request says
            return self.user
        actor = str(data.get("actor", ""))
        if not ACTOR_RE.match(actor):
            raise ValidationError("invalid actor")
        return actor

    def do_GET(self):
        """Purpose: entry point for GET requests (called by BaseHTTPRequestHandler).
        Inputs:  none; the request is in self.path / self.headers.
        Returns: None; the answer is sent by dispatch.
        Fails:   as dispatch (errors become JSON replies).
        Feeds:   dispatch("GET")."""
        self.dispatch("GET")

    def do_POST(self):
        """Purpose: entry point for POST requests (called by BaseHTTPRequestHandler).
        Inputs:  none; the request is in self.path / self.headers / self.rfile.
        Returns: None; the answer is sent by dispatch.
        Fails:   as dispatch (errors become JSON replies).
        Feeds:   dispatch("POST")."""
        self.dispatch("POST")

    def dispatch(self, method):
        """Purpose: route one /v1/ request to its route module and reply with the result as JSON.
        Inputs:  method — "GET" or "POST"; self.path (URL-decoded path segments; the query string is ignored), the
                 Authorization header (see authorize) and, for POST, the JSON body (see body; actor from actor()).
        Returns: None; replies 200 with the result (get_route for GET, post_route for POST).
        Fails:   never raises; replies 403 "peer not allowed" when the peer uid is not in allowed_uids; 404 "not found"
                 for a path outside /v1 or an unknown route; 401/403 from authorize; 400 with the message for
                 ValidationError; 400 "malformed request" for ValueError/JSON errors; 500 "internal error" (traceback to
                 stderr) for anything else.
        Feeds:   do_GET, do_POST."""
        if self.peer_uid() not in self.allowed_uids:
            return self.reply(403, {"error": "peer not allowed"})
        try:
            parts = [urllib.parse.unquote(p) for p in urllib.parse.urlsplit(self.path).path.strip("/").split("/")]
            if parts[:1] != ["v1"]:
                return self.reply(404, {"error": "not found"})
            route = parts[1:]
            refused = self.authorize(method, route)
            if refused:
                return self.reply(refused[0], {"error": refused[1]})
            if method == "GET":
                return self.reply(200, get_route(route, self.user))
            data = self.body()
            return self.reply(200, post_route(route, self.actor(data), data, self.perms, self.session))
        except RouteNotFound:
            self.reply(404, {"error": "not found"})
        except ValidationError as exc:
            self.reply(400, {"error": str(exc)})
        except (ValueError, json.JSONDecodeError):
            self.reply(400, {"error": "malformed request"})
        except Exception:                   # never leak internals to the caller; the journal gets the traceback
            traceback.print_exc()
            self.reply(500, {"error": "internal error"})
