import os
import pty
import select

from fabriclib.common.errors import ValidationError

TIMEOUT = 120        # seconds without output before age is taken to hang


def _pump(master, rout, win, data, passphrase):
    """Purpose: feed age its input and passphrase, and collect its output and terminal text.
    Inputs:  master — the pty's master fd (age's terminal); rout — read end of age's stdout; win — write end of its
             stdin (closed here once data is written); data — bytes for stdin, or None; passphrase — str or None,
             typed at each prompt that names a passphrase.
    Returns: (stdout bytes, terminal text).
    Fails:   ValidationError when age prints nothing for TIMEOUT seconds.
    Feeds:   run_age."""
    if data:
        os.write(win, data)
    os.close(win)
    out, tty, typed = [], b"", 0
    fds = [master, rout]
    while fds:
        ready, _, _ = select.select(fds, [], [], TIMEOUT)
        if not ready:
            raise ValidationError("age stopped answering: no output for 2 minutes")
        for fd in ready:
            try:
                chunk = os.read(fd, 1 << 16)
            except OSError:          # the pty's slave side closed: age has exited
                chunk = b""
            if not chunk:
                fds.remove(fd)
            elif fd == rout:
                out.append(chunk)
            else:
                tty += chunk
                while passphrase is not None and typed < tty.lower().count(b"passphrase"):
                    os.write(master, passphrase.encode() + b"\n")
                    typed += 1
    return b"".join(out), tty.decode(errors="replace")


def run_age(args, data=None, passphrase=None, identity=None):
    """Purpose: run `age` on small data (a bundle's key, decision 2.1.3.6) with any passphrase typed on its terminal,
             never on its command line or in its environment (global Rule 10). Debian's and Ubuntu's age (1.1, 1.2)
             read a passphrase only from a terminal, so age runs on a pty of its own; its data goes through pipes.
    Inputs:  args — age's arguments after "age"; an identity is passed as "-i" "{identity}", replaced here by a
             /dev/fd path to a pipe holding it. data — bytes for age's stdin, or None; passphrase — str, typed at
             each prompt (twice when encrypting, as age confirms it); identity — str, a private key, or None.
    Returns: age's stdout, bytes.
    Fails:   ValidationError when age fails (its last terminal line, a wrong passphrase or key, says why) or
             hangs; OSError when age is not installed.
    Feeds:   seal_bundle_key, open_bundle_key."""
    rin, win = os.pipe()
    rout, wout = os.pipe()
    keep = []
    if identity is not None:
        rid, wid = os.pipe()
        os.write(wid, identity.encode() + b"\n")
        os.close(wid)
        keep.append(rid)
        args = [f"/dev/fd/{rid}" if a == "{identity}" else a for a in args]
    pid, master = pty.fork()
    if pid == 0:                                   # age, on the pty as its terminal
        try:
            os.dup2(rin, 0)
            os.dup2(wout, 1)
            for fd in (rin, win, rout, wout):
                os.close(fd)
            os.execvp("age", ["age", *args])
        finally:
            os._exit(127)
    for fd in (rin, wout, *keep):
        os.close(fd)
    try:
        out, tty = _pump(master, rout, win, data, passphrase)
    finally:
        os.close(rout)
        os.close(master)
        _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code == 127:
        raise OSError("age is not installed (the fabricctl package depends on it: apt install age)")
    if code != 0:
        last = [line.strip() for line in tty.splitlines() if line.strip()]
        raise ValidationError(f"age failed: {last[-1] if last else 'no reason given'}")
    return out
