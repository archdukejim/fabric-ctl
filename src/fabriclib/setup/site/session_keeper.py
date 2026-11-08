import hmac
import secrets
import threading
import time

from fabriclib.setup.site.constants import SESSION_IDLE_SECONDS, TICKET_SECONDS, WRONG_TRIES
from fabriclib.setup.site.new_code import new_code


class SessionKeeper:
    """The one-time code and the one session it opens (manual 1.3.6.3). This, as root, judges; the listener asks."""

    def __init__(self, say, idle=SESSION_IDLE_SECONDS):
        """Purpose: make the first code.
        Inputs:  say — callable(text), the terminals: a replaced code is printed there and nowhere else; idle — seconds
                 a session lasts without activity (tests give their own).
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        self.say, self.idle = say, idle
        self.lock = threading.Lock()
        self.code, self.wrong = new_code(), 0
        self.token, self.csrf = "", ""
        self.ticket, self.ticket_until = "", 0.0
        self.seen = self.active = time.monotonic()

    def judge(self, typed):
        """Purpose: judge one try. Wrong ones count, and the last replaces the code, the terminals printing the new one.
                 A right one opens a session, unless one is open: then the browser is asked first (decision 2.1.8.62)
                 and gets a single-use ticket to confirm with, never the code.
        Inputs:  typed — str, as the form gave it (any case).
        Returns: dict: result ok, wrong (with left), replaced, or elsewhere (with ticket).
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        typed = str(typed).strip().upper()
        with self.lock:
            if not hmac.compare_digest(typed.encode(), self.code.encode()):
                self.wrong += 1
                if self.wrong >= WRONG_TRIES:
                    self.code, self.wrong = new_code(), 0
                    self.say("\n  Too many wrong tries at the site: its code is replaced. "
                             f"One-time code:  {self.code}\n")
                    return {"result": "replaced"}
                return {"result": "wrong", "left": WRONG_TRIES - self.wrong}
            self.wrong = 0
            if self.token:
                self.ticket, self.ticket_until = secrets.token_urlsafe(32), time.monotonic() + TICKET_SECONDS
                return {"result": "elsewhere", "ticket": self.ticket}
            return self._open()

    def take_over(self, ticket):
        """Purpose: the confirmation that ends the open session and opens one here; a ticket works once, while fresh.
        Inputs:  ticket — str, from the form.
        Returns: dict: result ok, or stale.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        with self.lock:
            fresh = self.ticket and time.monotonic() < self.ticket_until
            if not (fresh and hmac.compare_digest(str(ticket).encode(), self.ticket.encode())):
                return {"result": "stale"}
            return self._open()

    def _open(self):
        """Purpose: a new session; any earlier one, and any ticket, are over.
        Inputs:  none (the lock held).
        Returns: {"result": "ok"}.
        Fails:   never.
        Feeds:   judge, take_over."""
        self.token, self.csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.ticket = ""
        self.seen = self.active = time.monotonic()
        return {"result": "ok"}

    def noted(self, kind):
        """Purpose: the listener's word that a person is here: a request counts against the site's idle limit and the
                 session's; an open stream keeps the session.
        Inputs:  kind — "active" or "alive".
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        self.seen = time.monotonic()
        if kind == "active":
            self.active = self.seen

    def expired(self):
        """Purpose: end the session after its idle time (decision 2.1.8.62); the code then opens a new one.
        Inputs:  none.
        Returns: True when a session ended now.
        Fails:   never.
        Feeds:   setup/site/guided_site's watch."""
        with self.lock:
            if self.token and time.monotonic() - self.seen > self.idle:
                self.token = self.csrf = self.ticket = ""
                return True
            return False

    def forget(self):
        """Purpose: nothing of the code or the session stays in memory once the site has stopped.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        self.code = self.token = self.csrf = self.ticket = ""
