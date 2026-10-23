import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler

from webui import agentclient as actions
from webui import views
from webui.devpreview.dev_state import DevState
from webui.devpreview.fabric_rules import FABRIC_PERMISSIONS
from webui.httpio.read_form import read_form
from webui.routes.get_page import get_page
from webui.routes.post_action import post_action

TOGGLES = ("fresh", "off")          # the preview's own switches (the DNS filter's first fetch; DHCP off)


class _DevOIDC:
    """The preview's sign-out: back to the Overview (there is no Keycloak)."""

    @staticmethod
    def logout_url(id_token, back):
        """Purpose: Where sign-out goes in the preview.
        Inputs:  id_token, back — ignored.
        Returns: "/".
        Fails:   never.
        Feeds:   post_action (/logout)."""
        return "/"


class _DevApp:
    """What the real routes read of the production App: a lock, the sessions, the public address, the sign-out."""

    def __init__(self):
        """Purpose: The preview's app.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   DevHandler.app."""
        self.lock = threading.Lock()
        self.sessions = {}
        self.public_url = "http://127.0.0.1"
        self.sso_origin = ""
        self.issuer_dn = None
        self.oidc = _DevOIDC()


class DevHandler(BaseHTTPRequestHandler):
    """One dev-preview request: the production routes and pages (src/webui/routes, views) over in-memory sample data
    (fake_agent answers every agent call); no sign-in, no certificate, nothing saved."""
    state = DevState()
    app = _DevApp()
    who = {"user": "dev", "perms": sorted(FABRIC_PERMISSIONS)}

    def log_message(self, fmt, *args):
        """Purpose: Silence BaseHTTPRequestHandler's per-request log lines.
        Inputs:  fmt, *args — the standard log format and values; ignored.
        Returns: None.
        Fails:   never.
        Feeds:   — (called by http.server).
        """

    def send(self, status, body=b"", content_type="text/html; charset=utf-8", headers=None):
        """Purpose: Send one complete response with the same no-store and strict CSP headers as production.
        Inputs:  status — int HTTP status; body — str (UTF-8 encoded) or bytes; content_type — default HTML; headers
                 — list of extra (name, value) headers (Location, Content-Disposition).
        Returns: None.
        Fails:   OSError (e.g. BrokenPipeError) if the client has gone.
        Feeds:   the real routes, redirect, back, deny.
        """
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'")
        for k, v in headers or []:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def redirect(self, location, headers=None):
        """Purpose: 303 See Other, as production.
        Inputs:  location — str; headers — extra headers.
        Returns: None.
        Fails:   as send.
        Feeds:   the real routes."""
        self.send(303, b"", headers=[("Location", location)] + list(headers or []))

    def back(self, location, msg="", err=""):
        """Purpose: After an action, go to a page with its outcome as the next page's message (production keeps it in
                 the session; the preview in its state).
        Inputs:  location — str; msg — what was done; err — why not.
        Returns: None; 303 sent.
        Fails:   as send.
        Feeds:   the real POST routes."""
        if msg or err:
            self.state.flash = {"err": str(err)} if err else {"ok": str(msg)}
        self.redirect(location)

    def deny(self, status, message):
        """Purpose: An error page, as production.
        Inputs:  status — int; message — str.
        Returns: None.
        Fails:   as send.
        Feeds:   the real routes."""
        self.send(status, views.error_page(status, message))

    def _session(self):
        """Purpose: The preview's signed-in person, shaped as production's session (signed in just now, so no
                 step-up; the setup wizard already opened once).
        Inputs:  none (reads DevHandler.who: user, perms).
        Returns: dict.
        Fails:   never.
        Feeds:   _run."""
        return {"user": self.who["user"], "csrf": "dev", "perms": list(self.who["perms"]), "id_token": "dev",
                "sid": "dev", "auth_at": 4102444800, "reminders": [], "wizard_opened": True, "preview": True}

    def _run(self, method):
        """Purpose: One request through the production routes, the preview's flash and toggles set around it, and the
                 agent's refusals turned into pages as production's handler turns them.
        Inputs:  method — "GET" or "POST".
        Returns: None.
        Fails:   an unexpected error propagates (http.server logs it and closes the connection).
        Feeds:   do_GET, do_HEAD, do_POST."""
        url = urllib.parse.urlsplit(self.path)
        path = url.path
        query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        with self.state.lock:
            if path == "/static/app.css" and method == "GET":
                return self.send(200, views.css(), "text/css; charset=utf-8")
            if path == "/preview/denied":          # what a refused sign-in looks like
                return self.send(403, views.error_page(403, "Your account is not a person of this domain."))
            sess = self._session()
            self.state.toggles = {k: query[k] for k in TOGGLES if query.get(k)}
            actions.set_token("dev")
            try:
                if method == "POST":
                    form = read_form(self.headers, self.rfile)
                    if path == "/logout":
                        return self.redirect("/")
                    return post_action(self, sess, path, form)
                sess["flash"], self.state.flash = self.state.flash, None
                return get_page(self, sess, path, query)
            except actions.ValidationError as exc:
                return self.deny(400, str(exc))
            except actions.PermissionDenied as exc:
                return self.deny(403, f"Not allowed: {exc}.")
            except actions.AgentError as exc:
                return self.deny(503, f"The dev preview's agent failed: {exc}")

    def do_GET(self):
        """Purpose: Show a page.
        Inputs:  none (reads self.path).
        Returns: None.
        Fails:   as _run.
        Feeds:   — (called by http.server)."""
        self._run("GET")

    def do_HEAD(self):
        """Purpose: HEAD as GET, without the body.
        Inputs:  none.
        Returns: None.
        Fails:   as _run.
        Feeds:   — (called by http.server)."""
        self._run("GET")

    def do_POST(self):
        """Purpose: Act out a form post (no CSRF or sign-in check in the preview).
        Inputs:  none (reads self.path, the headers and the body).
        Returns: None.
        Fails:   as _run.
        Feeds:   — (called by http.server)."""
        self._run("POST")
