import os
import pwd
import socket
import subprocess
import sys
import tempfile

from fabriclib.common.paths import LIB_DIR
from fabriclib.setup.errors import SetupError

SCRIPT = ("fabriclib", "setup", "site", "listener", "site_main.py")


def start_listener(sock, cert_pem, key_pem, lib_dir=LIB_DIR, user="nobody"):
    """Purpose: start the site's unprivileged listener (manual 1.3.6.3). It gets, as inherited descriptors only, the
             listening socket, its end of a socket pair only the two can use, and the certificate and key in a memory
             file, never on a disk. It starts a session of its own: it must not hold root's terminal.
    Inputs:  sock — the listening socket; cert_pem, key_pem — str; lib_dir — the folder holding fabriclib, readable by
             the user; user — the account it runs as (None: this one; tests only).
    Returns: (process, setup's end of the socket pair).
    Fails:   SetupError when the account is missing or the process cannot start; a failure after the start shows on
             the first read of the link (GuidedSite says why from the process's stderr).
    Feeds:   setup/site/guided_site."""
    ours, theirs = socket.socketpair()
    memory = os.memfd_create("fabric-setup-site")
    errors = tempfile.TemporaryFile()
    try:
        os.write(memory, (cert_pem + key_pem).encode())
        fds = (sock.fileno(), theirs.fileno(), memory)
        as_user = {}
        if user:
            try:
                account = pwd.getpwnam(user)
            except KeyError:
                raise SetupError(f"the setup site runs as the account {user}, and this host has none. Run Guided here "
                                 "instead: sudo fabricctl setup --terminal. Nothing was changed.") from None
            as_user = {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": []}
        try:
            process = subprocess.Popen([sys.executable, "-I", os.path.join(lib_dir, *SCRIPT), *map(str, fds)],
                                       pass_fds=fds, cwd="/", env={"PATH": "/usr/bin:/bin"}, start_new_session=True,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors, **as_user)
        except OSError as e:
            raise SetupError(f"the setup site could not start: {e}. Run Guided here instead: sudo fabricctl setup "
                             "--terminal. Nothing was changed.") from None
    except BaseException:
        ours.close()
        errors.close()
        raise
    finally:
        os.close(memory)
        theirs.close()
    process.errors_file = errors
    return process, ours
