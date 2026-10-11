import hmac
import sys
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler

from webui import agentclient as actions
from webui import views
from webui.app_state import App
from webui.constants import NO_CERT
from webui.httpio.read_form import read_form
from webui.routes.get_page import get_page
from webui.routes.post_action import post_action
from webui.security.verified_client_cert import verified_client_cert
from webui.session.find_session import find_session
from webui.session.finish_login import finish_login
from webui.session.start_login import start_login


class Handler(BaseHTTPRequestHandler):
    """One web UI request: the security gates (client certificate, session, CSRF and Origin), then the routes in
    src/webui/routes — errors become error pages."""
    server_version = "fabric-web"
    sys_version = ""
    app: App = None

    def address_string(self):
        """Purpose: Name the client in log lines: the address nginx forwarded, since the unix socket has none.
        Inputs:  none (reads the X-Real-IP request header).
        Returns: the X-Real-IP value, or 'nginx' when it is absent.
        Fails:   never.
        Feeds:   log_message.
        """
        return self.headers.get("X-Real-IP", "nginx")

    def log_message(self, fmt, *args):
        """Purpose: Write one request or error log line to stderr (the container log), prefixed with the client address.
        Inputs:  fmt — %-format str; args — its values (both from BaseHTTPRequestHandler).
        Returns: None.
        Fails:   never in practice (TypeError only if fmt and args did not match).
        Feeds:   — (called by BaseHTTPRequestHandler).
        """
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def send(self, status, body=b"", content_type="text/html; charset=utf-8", headers=None):
        """Purpose: Send a complete response with the fixed security headers.
        Inputs:  status — int HTTP status; body — bytes or str (str is UTF-8 encoded), default empty; content_type —
                 default text/html; headers — list of (name, value) extra headers, e.g. Location, Set-Cookie.
        Returns: None; the response is written (no body for HEAD).
        Fails:   OSError (e.g. BrokenPipeError) when nginx has closed the connection.
        Feeds:   every route, redirect and deny.
        Notes:   Cache-Control no-store, nosniff, no referrer, no framing, COOP same-origin and a CSP without any script
                 source: styles and images from self only, forms may post to self and the Keycloak origin (its login
                 form).
        """
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # same-origin, not no-referrer: with no-referrer a browser sends "Origin: null" on its own form posts, which the
        # CSRF check refuses, so every button failed (2.3.1.13 finding 9); other sites still get no referrer
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'self'; img-src 'self'; "
                         f"form-action 'self' {self.app.sso_origin}; frame-ancestors 'none'; base-uri 'none'")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def redirect(self, location, headers=None):
        """Purpose: Send a 303 See Other to a location.
        Inputs:  location — str URL or path; headers — optional list of extra (name, value) headers such as Set-Cookie.
        Returns: None; the 303 response is sent.
        Fails:   as send.
        Feeds:   the routes and the sign-in.
        """
        self.send(303, b"", headers=[("Location", location)] + list(headers or []))

    def deny(self, status, message):
        """Purpose: Send an error page with a status and a message.
        Inputs:  status — int HTTP status (400, 401, 403, 404, 500, 503); message — str shown to the person
                 (autoescaped).
        Returns: None; the error page is sent.
        Fails:   as send.
        Feeds:   the routes, the sign-in and handle_request.
        """
        self.send(status, views.error_page(status, message))

    def do_HEAD(self):
        """Purpose: Answer HEAD exactly like GET; send leaves out the body.
        Inputs:  the request, as do_GET.
        Returns: None; the response is sent.
        Fails:   as handle_request.
        Feeds:   — (called by BaseHTTPRequestHandler).
        """
        self.do_GET()

    def do_GET(self):
        """Purpose: Entry point for GET requests.
        Inputs:  the request (path, headers).
        Returns: None; the response is sent by handle_request('GET').
        Fails:   as handle_request.
        Feeds:   — (called by BaseHTTPRequestHandler and do_HEAD).
        """
        self.handle_request("GET")

    def do_POST(self):
        """Purpose: Entry point for POST requests.
        Inputs:  the request (path, headers, body).
        Returns: None; the response is sent by handle_request('POST').
        Fails:   as handle_request.
        Feeds:   — (called by BaseHTTPRequestHandler).
        """
        self.handle_request("POST")

    def handle_request(self, method):
        """Purpose: Run every request through the security gates, then route it, and turn errors into error pages.
        Inputs:  method — 'GET' or 'POST'. Reads the path and query (first value per key), the client-certificate
                 headers, the session cookie, and for POST the Origin header and the form's csrf field.
        Returns: the response: GET /static/app.css → 200 stylesheet; GET /login and GET /oidc/callback → start_login /
                 finish_login (no session needed); no valid session → 303 to /login; POST → post_action; GET →
                 get_page.
        Fails:   403 without an accepted client certificate (when the web console requires one); 403 'CSRF check
                 failed' when Origin is not public_url or csrf does not match the session's; 400 with the message on
                 agentclient.ValidationError; 303 to /login on AuthError; 403 'Not allowed: …' on PermissionDenied;
                 503 on AgentError; 500 on anything else (traceback to stderr).
        Feeds:   — (called by do_GET, do_HEAD, do_POST).
        Notes:   It first clears the agent token for this thread, then sets the session's ID token so every
                 fabric-agent call runs as the signed-in person; fabric-agent enforces the permissions.
        """
        actions.set_token(None)          # this thread may have served someone else before
        try:
            self.app.sweep()
            # gates 1, 2 and 5 read the certificate only while the web console requires one (webui_client_cert)
            cert = verified_client_cert(self.headers, self.app.issuer_dn) if self.app.client_cert else NO_CERT
            if not cert:
                return self.deny(403, "A client certificate issued by this fabric's certificate authority is required.")
            url = urllib.parse.urlsplit(self.path)
            path = url.path
            query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}

            if path == "/static/app.css" and method == "GET":
                return self.send(200, views.css(), "text/css; charset=utf-8")
            if path == "/login" and method == "GET":
                return start_login(self, cert, query.get("next", "/"))
            if path == "/oidc/callback" and method == "GET":
                return finish_login(self, cert, query)

            sess = find_session(self.app, self.headers, cert)
            if not sess:
                return self.redirect("/login")
            actions.set_token(sess["id_token"])

            if method == "POST":
                origin = self.headers.get("Origin", "")
                form = read_form(self.headers, self.rfile)
                csrf = form.get("csrf", "")
                if (origin != self.app.public_url or not isinstance(csrf, str)
                        or not hmac.compare_digest(csrf, sess["csrf"])):
                    return self.deny(403, "Request rejected (CSRF check failed). Reload the page and try again.")
                return post_action(self, sess, path, form)
            return get_page(self, sess, path, query)
        except actions.ValidationError as exc:
            self.deny(400, str(exc))
        except actions.AuthError:
            self.redirect("/login")
        except actions.PermissionDenied as exc:
            self.deny(403, f"Not allowed: {exc}.")
        except actions.AgentError:
            traceback.print_exc()
            self.deny(503, "The fabric-agent service is unavailable. See `journalctl -u fabric-agent`.")
        except Exception:                   # never show internals; the container log gets the traceback
            traceback.print_exc()
            self.deny(500, "Internal error. See `journalctl -u webui`.")
