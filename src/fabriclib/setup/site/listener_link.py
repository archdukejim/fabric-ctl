import json
import socket
import struct
import subprocess
import threading

from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.start_listener import start_listener


SEND_SECONDS = 30          # a listener that stops reading must not stop setup
MAX_LINE = 1024 * 1024


class ListenerLink:
    """The one listener process and the socket pair to it: what root says, and what it says back (manual 1.3.6.3)."""

    def __init__(self, lib_dir, user):
        """Purpose: hold how a listener starts; nothing starts until start().
        Inputs:  lib_dir, user — start_listener's.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        self.lib_dir, self.user = lib_dir, user
        self.process = self.link = None
        self.sending = threading.Lock()   # two threads send, and a message is one line

    def start(self, sock, cert, key, hello, on_message):
        """Purpose: start a listener on this certificate, tell it all it needs, and read its messages.
        Inputs:  sock — the listening socket; cert, key — str; hello — its first message; on_message — callable(dict),
                 called from the reading thread.
        Returns: None, once it says it is ready.
        Fails:   SetupError when it dies before that, with its stderr's last words.
        Feeds:   setup/site/guided_site."""
        self.process, self.link = start_listener(sock, cert, key, self.lib_dir, self.user)
        self.link.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", SEND_SECONDS, 0))
        ready = threading.Event()
        self.send(hello)
        threading.Thread(target=self._pump, args=(self.link, ready, on_message), daemon=True).start()
        if not ready.wait(15):
            self.process.errors_file.seek(0)
            why = self.process.errors_file.read().decode("utf-8", "replace").strip()[-400:]
            raise SetupError(f"the setup site could not start: {why or 'it did not answer'}. Run Guided here instead: "
                             "sudo fabricctl setup --terminal. Nothing was changed.")

    def send(self, message):
        """Purpose: tell the listener something.
        Inputs:  message — dict.
        Returns: None.
        Fails:   never: a listener that has gone is found by whoever waits on it.
        Feeds:   setup/site/guided_site."""
        try:
            with self.sending:
                self.link.sendall((json.dumps(message) + "\n").encode())
        except (OSError, AttributeError):
            pass

    def _pump(self, link, ready, on_message):
        """Purpose: read one listener's messages until it ends: a thread, so a code can be judged while setup waits.
        Inputs:  link — the socket; ready — Event set when it says it is ready; on_message — as start.
        Returns: None.
        Fails:   never; a closed link, or a line that is no message from the listener, ends it (the process is then
                 stopped by whoever waits on it).
        Feeds:   start."""
        try:
            with link.makefile("r", encoding="utf-8") as lines:
                while True:
                    line = lines.readline(MAX_LINE)
                    if not line.endswith("\n"):
                        return
                    message = json.loads(line)
                    if not isinstance(message, dict):
                        return
                    if message.get("t") == "ready":
                        ready.set()
                    else:
                        on_message(message)
        except (OSError, ValueError):
            pass

    def stop(self):
        """Purpose: end the listener: it ends with its link.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        if self.link:
            try:
                self.link.shutdown(socket.SHUT_RDWR)  # the reading thread holds it open: close alone would not end it
            except OSError:
                pass
            self.link.close()
            self.link = None
        if self.process:
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:      # it must not outlive setup
                self.process.kill()
                self.process.wait()
            self.process.errors_file.close()
            self.process = None
