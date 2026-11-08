import json
import os
import socket
import time

from fabriclib.setup.site.listener.check_verdict import check_verdict
from fabriclib.setup.site.listener.page_for import page_for
from fabriclib.setup.site.listener.render_page import render_page
from fabriclib.setup.site.listener.request_base import COOKIE, RequestBase

STREAM_SILENCE_MS = 30_000
TYPES = {".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml"}
# every way into the site, for the entry-point inventory (manual 3.1.2.5): do_GET and do_POST route by this table
ROUTES = {("get", "/"): "_home", ("get", "/events"): "_events", ("get", "/static/*"): "_static",
          ("get", "/root-ca.crt"): "_root_ca", ("get", "/check/*"): "_check",
          ("get", "/check-result/*"): "_check_result",
          ("post", "/code"): "_code", ("post", "/answer"): "_answer", ("post", "/cancel"): "_cancel",
          ("post", "/finish"): "_finish"}
# what a browser whose session has ended is told (decision 2.1.8.62)
ENDED = {"taken": "This session was ended from another browser, which now holds setup. Use that browser, or enter "
                  "the code here to take it back.",
         "idle": "The session ended after 15 minutes without activity. Enter the code again."}


def _route(verb, path):
    """Purpose: the handler's method for a request.
    Inputs:  verb — "get" or "post"; path — the URL's path.
    Returns: (method name or None, the last segment for a /x/* route).
    Fails:   never.
    Feeds:   RequestBase._dispatch."""
    if (verb, path) in ROUTES:
        return ROUTES[(verb, path)], ""
    head, _, tail = path.rpartition("/")
    if tail and "/" not in tail and (verb, f"{head}/*") in ROUTES:
        return ROUTES[(verb, f"{head}/*")], tail
    return None, ""


class RequestHandler(RequestBase):
    """The site's pages and forms. It routes only: what is asked, and what is accepted, is setup's (1.3.6.4)."""

    route = staticmethod(_route)

    def _note_activity(self, kind="active"):
        """Purpose: tell setup a person is here: requests count against the idle limit, an open stream only says the
                 session's browser is still there.
        Inputs:  kind — "active" or "alive".
        Returns: None.
        Fails:   OSError when setup has gone.
        Feeds:   the routes."""
        self.server.control.send({"t": kind})

    def _home(self):
        """Purpose: the site's one page address: the code form without a session, otherwise what is now; just after an
                 answer it waits a little for what setup says next.
        Inputs:  none.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        state = self.server.state
        if state.phase == "closed":
            self._send(200, page_for(state))
            return
        if not self._signed_in():
            self._send(200, self._code_page(ENDED.get(self._ended(), "")))
            return
        self._note_activity()
        with state.changed:
            state.changed.wait_for(lambda: state.phase != "working", timeout=10)
        self._send(200, page_for(state))

    def _code(self):
        """Purpose: try the one-time code. Setup judges it: this process does not know it.
        Inputs:  the form: code.
        Returns: None: a session and the next page; otherwise the form again, saying why.
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        form = self._form()
        if form is None:
            return
        state = self.server.state
        if "ticket" in form:             # the confirmation to take the session over (decision 2.1.8.62)
            reply = self.server.control.request({"t": "takeover", "ticket": form["ticket"]})
        else:
            reply = self.server.control.request({"t": "code", "code": form.get("code", "")})
        result = reply.get("result")
        if result == "ok":
            # no Max-Age: the cookie, and with it the session for this browser, goes when the browser is closed
            cookie = f"{COOKIE}={state.token}; Path=/; Secure; HttpOnly; SameSite=Strict"
            self._headers(303, length=0, extra=[("Location", "/"), ("Set-Cookie", cookie)])
            return
        if result == "elsewhere":
            self._send(409, render_page(state, "takeover", "Open setup", step=0, stream=False,
                                        ticket=reply.get("ticket", "")))
            return
        why = {"wrong": f"That is not the code. {reply.get('left', 0)} tries left before it is replaced.",
               "replaced": "Too many wrong tries: that code is gone. The host's terminal shows a new one.",
               "stale": "That confirmation is no longer valid: it works once, for two minutes. Enter the code again."
               }.get(result, "Setup did not answer.")
        self._send(403 if result in ("wrong", "replaced", "stale") else 409, self._code_page(why))

    def _code_page(self, error):
        """Purpose: the code form, saying why it is shown again when there is a reason.
        Inputs:  error — str, "" for none.
        Returns: str, the page.
        Fails:   never.
        Feeds:   _home, _code."""
        state = self.server.state
        return render_page(state, "code", "Open setup", step=0, stream=False, error=error,
                           fingerprint=state.fingerprint)

    def _answer(self):
        """Purpose: pass an answer to setup, which checks it as on the terminal; a bad one comes back as the same
                 question, saying why (manual 1.3.6.4).
        Inputs:  the form: csrf, seq, value.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        form = self._session_form()
        if form is None:
            return
        state = self.server.state
        with state.changed:
            current = state.phase == "question" and state.question and str(state.question.get("seq")) == form.get("seq")
            if current:
                state.working()
        if not current:
            self._see()                  # a second click, or an old page: what is asked now is shown
            return
        self.server.control.send({"t": "answer", "seq": form.get("seq"), "value": form.get("value", "")})
        self._see()

    def _cancel(self):
        """Purpose: leave before Proceed; setup closes the site with nothing changed.
        Inputs:  the form: csrf.
        Returns: None; after Proceed it is refused, saying the work goes on.
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        if self._session_form() is not None:
            if self.server.state.phase not in ("question", "working"):
                self._refuse(409, "Refused: Proceed has been chosen and setup's work goes on. Nothing here cancels it.")
                return
            self.server.control.send({"t": "cancel"})
            self._send(200, render_page(self.server.state, "closed", "The site has closed", stream=False,
                                        why="Setup was cancelled here. Nothing was changed."))

    def _finish(self):
        """Purpose: the person is done: setup stops the site.
        Inputs:  the form: csrf.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        if self._session_form() is not None:
            self.server.control.send({"t": "finish"})
            self._send(200, render_page(self.server.state, "closed", "The site has closed", stream=False,
                                        why="This temporary site has stopped; any port it opened is closed."))

    def _static(self, name):
        """Purpose: the site's stylesheet, script and drawings: only files setup gave, by exact name.
        Inputs:  name — the last path segment.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        files = self.server.state.files
        kind = TYPES.get(os.path.splitext(name)[1])
        if not kind or name not in files:
            self._refuse(404, "There is no such file on this site.")
            return
        body = files[name].encode()
        self._headers(200, kind=kind + "; charset=utf-8", length=len(body))
        self.wfile.write(body)

    def _root_ca(self):
        """Purpose: offer fabric's root certificate (manual 1.3.6.6), public data, once setup has made it.
        Inputs:  none.
        Returns: None.
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        pem = self.server.state.finish.get("root_pem")
        if not pem:
            self._refuse(404, "There is no root certificate yet: setup has not finished.")
            return
        body = pem.encode()
        self._headers(200, kind="application/x-x509-ca-cert", length=len(body),
                      extra=[("Content-Disposition", 'attachment; filename="root-ca.crt"')])
        self.wfile.write(body)

    def _events(self):
        """Purpose: the live stream (manual 1.3.6.5): log lines with their number, so a reconnect misses none it can
                 replay, and the version of the page; a keep-alive says the browser is still there.
        Inputs:  ?after=N or Last-Event-ID: the lines already shown.
        Returns: None, when the connection ends.
        Fails:   OSError from a closed connection ends it.
        Feeds:   ROUTES."""
        if not self._signed_in():
            self._refuse(401, "This browser does not hold setup's session.")
            return
        state = self.server.state
        try:
            sent = int(self.headers.get("Last-Event-ID") or self.query.get("after", ["0"])[0])
        except ValueError:
            sent = 0
        self.connection.settimeout(None)
        # a network that goes silent must end the stream: its writes would fit the send buffer for many minutes, each
        # saying the browser is still there, and the same code could not reconnect (manual 1.3.6.5)
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, STREAM_SILENCE_MS)
        self._headers(200, kind="text/event-stream; charset=utf-8")
        version, ticked = None, 0.0
        while self._signed_in():         # a later session ends this one, and what it may read
            with state.changed:
                state.changed.wait_for(lambda: state.logged > sent or state.version != version, timeout=15)
                first = state.logged - len(state.log)
                start = max(sent, first)
                lines = state.log[start - first:]
                now_version, sent = state.version, start + len(lines)
            chunks = [f"id: {start + n + 1}\nevent: log\ndata: {line}\n\n" for n, line in enumerate(lines)]
            if now_version != version:
                chunks.append(f"event: phase\ndata: {now_version}\n\n")
                version = now_version
            self.wfile.write(("".join(chunks) or ": still here\n\n").encode())
            self.wfile.flush()
            if time.monotonic() - ticked > 10:
                self._note_activity("alive")
                ticked = time.monotonic()
        # the page reloads at once and is told why (decision 2.1.8.62)
        self.wfile.write(b"event: ended\ndata: 1\n\n")
        self.wfile.flush()

    def _check(self, nonce):
        """Purpose: the browser's request for the finish's check, sent to the console's name at this port (manual
                 1.3.6.6). It arriving means the browser trusted the certificate. Needs no session: the browser sends
                 no cookie across names.
        Inputs:  nonce — the page's token.
        Returns: None: 204.
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        checks = self.server.state.checks
        if len(checks) > 64:
            checks.clear()
        checks[nonce] = self.client_address[0]
        self._headers(204, length=0)

    def _check_result(self, nonce):
        """Purpose: what the finish's check found, joined with the host's own look at the console.
        Inputs:  nonce — the page's token; ?console=1: the browser reached the console itself.
        Returns: None: JSON (check_verdict).
        Fails:   OSError from a closed connection.
        Feeds:   ROUTES."""
        if not self._signed_in():
            self._refuse(401, "This browser does not hold setup's session.")
            return
        state, peer = self.server.state, self.client_address[0]
        name = state.finish.get("console_name", "")
        host = self.server.control.request({"t": "check"}, timeout=25).get("problem", "the host did not answer")
        verdict = check_verdict(state.name_seen(name, peer), state.checks.get(nonce) == peer,
                                self.query.get("console") == ["1"], host, name)
        body = json.dumps(verdict).encode()
        self._headers(200, kind="application/json", length=len(body))
        self.wfile.write(body)
