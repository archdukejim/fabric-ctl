#!/usr/bin/env python3
"""PyKMIP's server for the openbao suite (run.py), with one fix: a session whose client has gone ends (2.3.1.57).

PyKMIP 0.10.0 ends a session only on its own ConnectionClosed; any other error is logged and the session's loop runs
again. Under Python 3.14 (Ubuntu 26.04) a client that went away gives BrokenPipeError, so that session's thread looped
without end and the server stopped answering every later request ("The read operation timed out"). A socket error
here now ends the session as a closed connection does. The test's stand-in for an HSM, not fabric's code: a real KMIP
device is not PyKMIP.

    python3 tests/openbao/kmip_server.py -f <kmip.conf> -l <kmip.log>     (pykmip-server's own arguments)
"""
import sys

from kmip.core import exceptions
from kmip.services.server import server, session

_loop = session.KmipSession._handle_message_loop


def _handle_message_loop(self):
    """Purpose: PyKMIP's own message loop, a socket error turned into the closed connection that ends the session.
    Inputs:  self — the KmipSession.
    Returns: None.
    Fails:   ConnectionClosed for an OSError (BrokenPipeError, ConnectionResetError, an SSL error); anything else
             as PyKMIP raises it.
    Feeds:   KmipSession.run, through the class attribute set below."""
    try:
        _loop(self)
    except OSError as exc:
        raise exceptions.ConnectionClosed(str(exc)) from exc


session.KmipSession._handle_message_loop = _handle_message_loop
if __name__ == "__main__":
    sys.exit(server.main())
