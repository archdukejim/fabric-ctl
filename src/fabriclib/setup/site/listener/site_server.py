import socket
import threading
from http.server import ThreadingHTTPServer

MAX_CONNECTIONS = 64
HANDSHAKE_SECONDS = 15


class SiteServer(ThreadingHTTPServer):
    """A threaded HTTPS server on a socket setup bound for it; the TLS handshake happens in the request's own thread,
    so one slow client cannot hold the rest up."""

    daemon_threads = True

    def __init__(self, fd, tls, handler, state, control):
        """Purpose: take over setup's listening socket.
        Inputs:  fd — int, the listening socket; tls — SSLContext; handler — the request handler class; state —
                 SiteState; control — ControlLink.
        Returns: None.
        Fails:   OSError on a bad descriptor.
        Feeds:   listener/site_main."""
        super().__init__(("0.0.0.0", 0), handler, bind_and_activate=False)
        self.socket.close()
        self.socket = socket.socket(fileno=fd)
        self.tls, self.state, self.control = tls, state, control
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def get_request(self):
        """Purpose: accept one connection, wrapped in TLS, with no handshake yet.
        Inputs:  none.
        Returns: (TLS socket, address).
        Fails:   OSError as accept; socketserver ignores it for that connection.
        Feeds:   socketserver."""
        sock, address = self.socket.accept()
        sock.settimeout(HANDSHAKE_SECONDS)
        return self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address

    def verify_request(self, request, client_address):
        """Purpose: refuse a connection past the limit, so a flood cannot use up the host.
        Inputs:  request — the socket; client_address — tuple.
        Returns: bool; True holds a slot, which process_request_thread gives back.
        Fails:   never.
        Feeds:   socketserver."""
        return self.slots.acquire(blocking=False)

    def process_request_thread(self, request, client_address):
        """Purpose: serve one connection and give its slot back.
        Inputs:  request, client_address — as socketserver gives.
        Returns: None.
        Fails:   never; handle_error says nothing.
        Feeds:   socketserver."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        """Purpose: say nothing about a failed connection (a browser refusing the certificate is expected): the site
                 logs nothing (manual 1.3.6.3).
        Inputs:  request, client_address — unused.
        Returns: None.
        Fails:   never.
        Feeds:   socketserver."""
