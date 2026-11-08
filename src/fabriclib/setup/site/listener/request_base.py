import hmac
import ssl
import urllib.parse
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler

from fabriclib.setup.site.listener.render_page import render_page

COOKIE = "__Host-fabric-setup"
MAX_BODY = 64 * 1024


class RequestBase(BaseHTTPRequestHandler):
    """What every route of the site shares: headers, refusals, the Origin check, the session and the CSRF token."""

    protocol_version = "HTTP/1.1"
    server_version, sys_version = "fabric-setup-site", ""
    timeout = 30

    def log_message(self, format, *args):
        """Purpose: log nothing: a form's fields and the code never reach a log (manual 1.3.6.3).
        Inputs:  format, args — as http.server gives.
        Returns: None.
        Fails:   never.
        Feeds:   http.server."""

    def do_GET(self):
        """Purpose: route a GET.
        Inputs:  none (the request).
        Returns: None; the response is written.
        Fails:   never for a client's error (an answer says why); OSError from a closed connection ends it.
        Feeds:   http.server."""
        self._dispatch("get")

    def do_POST(self):
        """Purpose: route a POST: nothing changes without the Origin check.
        Inputs:  none (the request).
        Returns: None; the response is written.
        Fails:   as do_GET.
        Feeds:   http.server."""
        self._dispatch("post")

    def _dispatch(self, verb):
        """Purpose: find the route and run it; a request whose connection fails ends quietly.
        Inputs:  verb — "get" or "post".
        Returns: None.
        Fails:   never for ssl or connection errors (the connection just ends).
        Feeds:   do_GET, do_POST."""
        self.close_connection = True
        parts = urllib.parse.urlsplit(self.path)
        self.query = urllib.parse.parse_qs(parts.query)
        method, tail = self.route(verb, parts.path)
        try:
            if not method:
                self._refuse(404, "There is no such page on this site.")
            elif verb == "post" and not self._origin_ok():
                pass
            else:
                getattr(self, method)(tail) if tail else getattr(self, method)()
        except (ConnectionError, ssl.SSLError, TimeoutError):
            pass

    def _headers(self, status, kind="text/html; charset=utf-8", length=None, extra=()):
        """Purpose: a response's headers. Never Strict-Transport-Security: a person must be able to go past the first
                 certificate's warning, and to fabric's own certificate after it.
        Inputs:  status — int; kind — Content-Type; length — int or None; extra — (name, value) pairs.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   the routes."""
        state = self.server.state
        connect = "'self'"
        if state.finish.get("console_name"):
            name = state.finish["console_name"]
            connect += f" https://{name} https://{name}:{state.port}"
        if state.finish.get("signin_name"):      # the console's / redirects there, and a policy checks every hop
            connect += f" https://{state.finish['signin_name']}"
        self.send_response(status)
        self.send_header("Content-Type", kind)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        # same-origin, not no-referrer: with no-referrer a browser's form sends "Origin: null", which the Origin
        # check refuses
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         f"default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; "
                         f"connect-src {connect}; "
                         "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()

    def _send(self, status, page, extra=()):
        """Purpose: send a whole page.
        Inputs:  status — int; page — str; extra — header pairs.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   the routes."""
        body = page.encode()
        self._headers(status, length=len(body), extra=extra)
        self.wfile.write(body)

    def _see(self, path="/"):
        """Purpose: after a form: go and look at what is now (303).
        Inputs:  path — where.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   the POST routes."""
        self._headers(303, length=0, extra=[("Location", path)])

    def _refuse(self, status, why):
        """Purpose: refuse, saying why, changing nothing (manual 1.3.6.8).
        Inputs:  status — int; why — str.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   the routes."""
        self._send(status, render_page(self.server.state, "refused", "Refused", stream=False, why=why))

    def _origin_ok(self):
        """Purpose: the Origin check on every change (manual 1.3.6.3): the form must come from this site's own pages.
        Inputs:  none (the Origin and Host headers).
        Returns: bool; False has already refused, naming what came.
        Fails:   OSError from a closed connection.
        Feeds:   _dispatch."""
        origin, host = self.headers.get("Origin", ""), self.headers.get("Host", "")
        if host and origin == f"https://{host}":
            return True
        self._refuse(403, f"Refused: this request came from {origin or 'no page at all'}, not from this site's own "
                          "page. "
                          "Nothing was changed.")
        return False

    def _signed_in(self):
        """Purpose: whether this request holds the session (the cookie setup's code gave).
        Inputs:  none (the Cookie header; state.token).
        Returns: bool.
        Fails:   never.
        Feeds:   the routes."""
        token, cookie = self.server.state.token, self._cookie()
        return bool(token and cookie and hmac.compare_digest(cookie.encode(), token.encode()))

    def _cookie(self):
        """Purpose: the session cookie this request carries.
        Inputs:  none (the Cookie header).
        Returns: str, "" without one.
        Fails:   never.
        Feeds:   _signed_in, the routes."""
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", "")).get(COOKIE)
        except CookieError:              # a malformed cookie is no session
            cookie = None
        return cookie.value if cookie else ""

    def _ended(self):
        """Purpose: why this browser's session ended, when it held one that has (decision 2.1.8.62).
        Inputs:  none.
        Returns: "taken", "idle" or "".
        Fails:   never.
        Feeds:   the routes."""
        cookie = self._cookie()
        return self.server.state.ended.get(cookie, "") if cookie else ""

    def _form(self):
        """Purpose: the POST's fields, at most MAX_BODY bytes.
        Inputs:  none (the request's body).
        Returns: {name: first value}; None when the length is no length or too long, already refused.
        Fails:   OSError from a closed connection.
        Feeds:   the POST routes."""
        given = self.headers.get("Content-Length") or "0"
        if not (given.isascii() and given.isdigit()):      # "-1" would read until the client stops, without limit
            self._refuse(400, "Refused: this request's length is not a number. Nothing was changed.")
            return None
        length = int(given)
        if length > MAX_BODY:
            self._refuse(413, "Refused: that answer is too long. Nothing was changed.")
            return None
        body = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(body, keep_blank_values=True).items()}

    def _session_form(self):
        """Purpose: a changing form's fields, after the session and the CSRF token (manual 1.3.6.3).
        Inputs:  none.
        Returns: the fields; None when refused, saying why.
        Fails:   as _form.
        Feeds:   the POST routes."""
        if not self._signed_in():
            self._refuse(403, "Refused: this browser does not hold setup's session. Nothing was changed.")
            return None
        form = self._form()
        if form is None:
            return None
        if not hmac.compare_digest(form.get("csrf", "").encode(), self.server.state.csrf.encode()):
            self._refuse(403, "Refused: this page is out of date (its security token is stale). Open the site again; "
                              "nothing was changed.")
            return None
        return form
