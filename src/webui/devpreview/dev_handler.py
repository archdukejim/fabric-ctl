import email.parser
import email.policy
import urllib.parse
from http.server import BaseHTTPRequestHandler

from webui.devpreview.dev_get_page import dev_get_page
from webui.devpreview.dev_post_action import dev_post_action
from webui.devpreview.dev_state import DevState
from webui.devpreview.fabric_rules import FABRIC_PERMISSIONS


class DevHandler(BaseHTTPRequestHandler):
    """One dev-preview request: the real pages over in-memory sample data; no sign-in, nothing saved."""
    state = DevState()
    ctx = {"user": "dev (preview)", "csrf": "dev", "dev": True, "perms": sorted(FABRIC_PERMISSIONS),
           "version": {"version": "dev preview", "build": "sample data · no sign-in · nothing is saved"}}

    def log_message(self, fmt, *args):
        """Purpose: Silence BaseHTTPRequestHandler's per-request log lines.
        Inputs:  fmt, *args — the standard log format and values; ignored.
        Returns: None.
        Fails:   never.
        Feeds:   — (called by http.server).
        """
        pass

    def send(self, status, body, ctype="text/html; charset=utf-8", location=None):
        """Purpose: Send one complete response with the same no-store and strict CSP headers as production.
        Inputs:  status — int HTTP status; body — str (UTF-8 encoded) or bytes; ctype — Content-Type, default HTML;
                 location — optional Location header for redirects.
        Returns: None.
        Fails:   OSError (e.g. BrokenPipeError) if the client has gone.
        Feeds:   dev_get_page, dev_post_action and their helpers.
        """
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        """Purpose: Show a page (dev_get_page) under the state lock.
        Inputs:  none (reads self.path).
        Returns: None.
        Fails:   as dev_get_page.
        Feeds:   — (called by http.server).
        """
        url = urllib.parse.urlsplit(self.path)
        with self.state.lock:
            dev_get_page(self, urllib.parse.unquote(url.path), dict(urllib.parse.parse_qsl(url.query)))

    def do_POST(self):
        """Purpose: Read a form post — urlencoded, or multipart keeping text fields only (file uploads are dropped); at
                 most 65536 bytes — and act it out (dev_post_action) under the state lock. No CSRF or sign-in check.
        Inputs:  none (reads self.path, the headers and the body).
        Returns: None.
        Fails:   as dev_post_action.
        Feeds:   — (called by http.server).
        """
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        body = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 65536))
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("multipart/form-data"):          # file inputs (HSM, CSR uploads): text fields only
            msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                f"Content-Type: {ctype}\r\n\r\n".encode() + body)
            form = {part.get_param("name", header="content-disposition"):
                    (part.get_payload(decode=True) or b"").decode(errors="replace")
                    for part in (msg.iter_parts() if msg.is_multipart() else []) if part.get_filename() is None}
        else:
            form = dict(urllib.parse.parse_qsl(body.decode(errors="replace"), keep_blank_values=True))
        with self.state.lock:
            dev_post_action(self, path, form)
