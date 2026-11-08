import os
import socket
import stat
import struct
import threading

from fabriclib.setup.site.constants import ATTACH_SOCKET

SEND_SECONDS = 2                 # a terminal that stops reading is dropped, and setup goes on


class AttachServer:
    """The running setup's socket for other terminals (decision 2.1.8.60): root's only, and one way. A terminal that
    attaches gets the greeting (URL, current code, fingerprint), then what setup prints; nothing it sends is read."""

    def __init__(self, greeting, path=ATTACH_SOCKET):
        """Purpose: hold what an attach is given; nothing listens until open().
        Inputs:  greeting — callable() -> str, what a terminal sees first, made when it attaches; path — the socket.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        self.greeting, self.path = greeting, path
        self.lock = threading.Lock()
        self.sock, self.viewers = None, []

    def open(self):
        """Purpose: listen at the socket, mode 0600, removing a socket a killed setup left there (only a socket).
        Inputs:  none.
        Returns: self.
        Fails:   OSError: the folder cannot be made, or something other than a socket is at the path.
        Feeds:   setup/site/guided_site."""
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        try:
            if stat.S_ISSOCK(os.lstat(self.path).st_mode):
                os.unlink(self.path)
        except FileNotFoundError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        saved = os.umask(0o177)          # never, even for a moment, a socket others may connect to
        try:
            sock.bind(self.path)
        finally:
            os.umask(saved)
        os.chmod(self.path, 0o600)
        sock.listen(4)
        self.sock = sock
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def _accept(self):
        """Purpose: take terminals as they come; one whose peer is not root is closed unanswered.
        Inputs:  none.
        Returns: None, once the socket is closed.
        Fails:   never.
        Feeds:   open, as a thread."""
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            _pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                   struct.calcsize("3i")))
            if uid != 0:
                conn.close()
                continue
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", SEND_SECONDS, 0))
            with self.lock:
                if self._send(conn, self.greeting()):
                    self.viewers.append(conn)

    def _send(self, conn, text):
        """Purpose: one write to one terminal.
        Inputs:  conn — socket; text — str.
        Returns: bool, whether it went; a terminal that failed is closed.
        Fails:   never.
        Feeds:   _accept, say."""
        try:
            conn.sendall(text.encode())
            return True
        except OSError:
            conn.close()
            return False

    def say(self, text):
        """Purpose: what setup prints, to every attached terminal; one gone or stuck is dropped.
        Inputs:  text — str.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site's say."""
        with self.lock:
            self.viewers = [conn for conn in self.viewers if self._send(conn, text)]

    def close(self, last=""):
        """Purpose: stop listening, remove the socket, and end every attach, telling each why.
        Inputs:  last — str, what the terminals are told last.
        Returns: None.
        Fails:   never.
        Feeds:   setup/site/guided_site."""
        if self.sock is None:
            return
        self.sock.close()
        self.sock = None
        try:
            os.unlink(self.path)
        except OSError:
            pass
        with self.lock:
            for conn in self.viewers:
                if last:
                    self._send(conn, last)
                conn.close()
            self.viewers = []
