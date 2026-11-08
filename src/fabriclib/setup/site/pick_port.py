import socket

from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.port_holder import port_holder


def pick_port(first, last, holder=port_holder):
    """Purpose: claim the site's TCP port (manual 1.3.6.7): the first of first..last nothing else holds, by binding it,
             never by assuming it is free.
    Inputs:  first, last — ints, the range; holder — callable(port) -> str, what holds a port.
    Returns: (listening socket, port, [what was found on the ports passed over]).
    Fails:   SetupError when every port is taken, saying what holds the first and offering --terminal. Nothing changed.
    Feeds:   setup/site/guided_site."""
    found = []
    for port in range(first, last + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            sock.listen(32)
        except OSError:
            sock.close()
            found.append(f"port {port} is taken by {holder(port)}")
            continue
        return sock, port, found
    raise SetupError(f"web-guided setup needs one TCP port from {first} to {last}, and all are taken ({first} by "
                     f"{holder(first)}). Free one, or run Guided here: sudo fabricctl setup --terminal. "
                     "Nothing was changed.")
