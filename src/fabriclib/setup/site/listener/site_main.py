#!/usr/bin/env python3
"""The temporary site's listener (manual 1.3.6.3): unprivileged, Python's standard library only, started by setup with
its listening socket, the control socket and the certificate as inherited descriptors.

    python3 -I site_main.py <listening fd> <control fd> <certificate fd>
"""
import ctypes
import os
import signal
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))))
from fabriclib.setup.site.listener.build_tls import build_tls  # noqa: E402
from fabriclib.setup.site.listener.control_link import ControlLink  # noqa: E402
from fabriclib.setup.site.listener.request_handler import RequestHandler  # noqa: E402
from fabriclib.setup.site.listener.site_server import SiteServer  # noqa: E402
from fabriclib.setup.site.listener.site_state import SiteState  # noqa: E402

PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS = 4, 38


def main(argv):
    """Purpose: start the site and run until setup closes the control link. Interrupts belong to setup, which decides
             what they mean; this process ends with the link. It can gain no privilege, and once the key is read no
             other process of its user can read this one's memory.
    Inputs:  argv — the three descriptors, as text.
    Returns: never returns normally (the link's end ends the process); 2 for wrong arguments.
    Fails:   OSError / ssl.SSLError / ValueError at start: the traceback on stderr, which setup shows.
    Feeds:   setup/site/start_listener."""
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    listening, control_fd, cert_fd = (int(a) for a in argv)
    for number in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
        signal.signal(number, signal.SIG_IGN)
    libc = ctypes.CDLL(None)
    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    control = ControlLink(socket.socket(fileno=control_fd), None)
    state = SiteState(control.read_hello())
    control.state = state
    tls = build_tls(f"/proc/self/fd/{cert_fd}", state)
    os.close(cert_fd)
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    server = SiteServer(listening, tls, RequestHandler, state, control)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    control.send({"t": "ready"})
    control.run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
