import threading
import time

LOG_LINES = 5000                # what a reconnecting page can still replay
SNI_SECONDS = 60                # how long a name seen in a TLS hello counts for the finish's check


class SiteState:
    """What the listener knows, all of it told by setup over the control link: it decides nothing about setup."""

    def __init__(self, hello):
        """Purpose: start from setup's first message.
        Inputs:  hello — dict: files {name: text}, port, fingerprint, temporary, phase, token, csrf, log, finish.
        Returns: None.
        Fails:   KeyError for a hello missing files or port (setup's own message).
        Feeds:   listener/site_main."""
        self.changed = threading.Condition()
        self.files, self.port = hello["files"], hello["port"]
        self.fingerprint = hello.get("fingerprint", "")
        self.temporary = hello.get("temporary", True)
        self.phase = hello.get("phase", "question")
        self.token, self.csrf = hello.get("token", ""), hello.get("csrf", "")
        self.finish = hello.get("finish") or {}
        self.question, self.why = None, ""
        self.log = []
        self.logged = 0                 # lines ever logged: an event's id, so a reconnect misses none it can replay
        self.partial = ""
        self.version = 1                # changes when the page shown should change
        self.seen_names = {}            # {name in a TLS hello: (time, peer address)}
        self.checks = {}                # {nonce: peer address} the finish's check reached, past TLS
        self.add_log(hello.get("log") or "")

    def add_log(self, text):
        """Purpose: append setup's output, whole lines becoming events.
        Inputs:  text — str, any chunk.
        Returns: None; waiting streams are woken.
        Fails:   never.
        Feeds:   apply, __init__."""
        with self.changed:
            lines = (self.partial + text).split("\n")
            self.partial = lines.pop()
            self.log.extend(lines)
            self.logged += len(lines)
            del self.log[:-LOG_LINES]
            self.changed.notify_all()

    def apply(self, message):
        """Purpose: take one message from setup (the control link's types: question, phase, session, log, finish).
        Inputs:  message — dict with "t".
        Returns: None; the version moves when the page should change.
        Fails:   never for a message of another type (ignored).
        Feeds:   listener/control_link."""
        kind = message.get("t")
        if kind == "log":
            self.add_log(message.get("text", ""))
            return
        with self.changed:
            if kind == "question":
                self.phase, self.question = "question", message
            elif kind == "phase":
                self.phase, self.why = message["phase"], message.get("why", "")
                self.finish = message.get("finish", self.finish)
                self.fingerprint = message.get("fingerprint", self.fingerprint)
                self.temporary = message.get("temporary", self.temporary)
            elif kind == "session":
                self.token, self.csrf = message["token"], message["csrf"]
            else:
                return
            self.version += 1
            self.changed.notify_all()

    def working(self):
        """Purpose: an answer went to setup: show it is being worked on until setup says what is next.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   listener/request_handler."""
        with self.changed:
            if self.phase == "question":
                self.phase = "working"
                self.version += 1
                self.changed.notify_all()

    def saw_name(self, name, peer):
        """Purpose: a TLS hello named this host: the name resolves here from that client, whatever follows (1.3.6.6).
        Inputs:  name — str, the SNI; peer — the client's address (str, or "").
        Returns: None.
        Fails:   never.
        Feeds:   listener/build_tls."""
        with self.changed:
            self.seen_names[name.lower()] = (time.monotonic(), peer)
            if len(self.seen_names) > 64:
                self.seen_names.pop(next(iter(self.seen_names)))

    def name_seen(self, name, peer):
        """Purpose: whether this client's TLS hello named this name, lately.
        Inputs:  name — str; peer — the client's address (str).
        Returns: bool.
        Fails:   never.
        Feeds:   listener/request_handler."""
        when, who = self.seen_names.get(name.lower(), (None, None))
        return when is not None and time.monotonic() - when < SNI_SECONDS and who in (peer, "")
