import codecs
import socket
import sys

from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.constants import ATTACH_SOCKET


def attach_site(record, path=ATTACH_SOCKET, out=None):
    """Purpose: `sudo fabricctl setup` while a Guided site runs (decision 2.1.8.60): attach to it, as tmux attach does,
             showing the URL, the current code and the fingerprint, then what setup prints. Ctrl-C only detaches.
    Inputs:  record — the site's port record (read_port_record); path — the attach socket; out — the terminal (default
             sys.stdout).
    Returns: 0, once detached or once the site has stopped.
    Fails:   SetupError: not root, or the running setup cannot be reached. Nothing is changed either way.
    Feeds:   setup/run_setup."""
    out = out or sys.stdout
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except PermissionError:
        sock.close()
        raise SetupError("a setup is running here with its site, and only root can attach to it: sudo fabricctl "
                         "setup") from None
    except OSError as e:
        sock.close()
        raise SetupError(f"a setup's site is running here (process {record['pid']}, TCP {record['port']}), but it "
                         f"cannot be attached to ({e.strerror or e}). Nothing was changed.") from None
    out.write("\n  Attached to the running setup. Ctrl-C detaches; setup and its site go on.\n")
    out.flush()
    text = codecs.getincrementaldecoder("utf-8")("replace")     # a character may be split between two reads
    try:
        with sock:
            while chunk := sock.recv(65536):
                out.write(text.decode(chunk))
                out.flush()
    except KeyboardInterrupt:
        out.write("\n  Detached. Setup and its site go on; sudo fabricctl setup attaches again.\n")
        return 0
    except OSError:
        pass
    out.write("\n  The setup site has stopped.\n")
    return 0
