import hmac
import secrets
import threading
import time

from fabriclib.setup.site.constants import SESSION_QUIET_SECONDS, WRONG_TRIES
from fabriclib.setup.site.new_code import new_code


class SessionKeeper:
    """The one-time code and the one session it opens (manual 1.3.6.3). This, as root, judges; the listener asks."""

    def __init__(self, say):
        """Purpose: make the first code.
        Inputs:  say — callable(text), the terminal: a replaced code is printed there and nowhere else.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        self.say = say
        self.lock = threading.Lock()
        self.code, self.wrong = new_code(), 0
        self.token, self.csrf = "", ""
        self.seen = self.active = time.monotonic()

    def judge(self, typed):
        """Purpose: judge one try. Wrong ones count, and the last replaces the code, the terminal printing the new one.
                 A right one opens one session: while that session's browser is around a second is refused; once it has
                 been quiet long enough, the same code reconnects (1.3.6.5), and the old session is over.
        Inputs:  typed — str, as the form gave it (any case).
        Returns: dict: result ok, wrong (with left), replaced or busy.
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
            if self.token and time.monotonic() - self.seen < SESSION_QUIET_SECONDS:
                return {"result": "busy"}
            self.wrong = 0
            self.token, self.csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.seen = self.active = time.monotonic()
            return {"result": "ok"}

    def noted(self, kind):
        """Purpose: the listener's word that a person is here: a request counts against the idle limit; an open stream
                 only says the session's browser is still there.
        Inputs:  kind — "active" or "alive".
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        self.seen = time.monotonic()
        if kind == "active":
            self.active = self.seen

    def forget(self):
        """Purpose: nothing of the code or the session stays in memory once the site has stopped.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        self.code = self.token = self.csrf = ""
