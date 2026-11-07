"""fabric-agent's held processes in the DC (manual 1.8.8.2, decision 2.1.8.35): `docker exec` and Python's start took
most
of a directory page's time on the test Pi (about 280 ms a call, several a page, 2.3.8.5.3), so the agent keeps up to two
`directory_op.py --serve` running and hands each its request on stdin, the password in it as before. Each answers one
JSON line per request and signs in once, as the same account. One that has died is replaced before it is asked."""
import json
import os
import select
import subprocess
import threading
import time

from fabriclib.common.errors import ValidationError

MAX_HELD = 2
_lock = threading.Condition()
_idle = {}          # container -> [processes free]
_count = {}         # container -> how many are running or lent
_enabled = False    # fabric-agent only: a short-lived command has nothing to hold


def enable():
    """Purpose: run_op and read_in_dc go through held processes from now on, in this process.
    Inputs:  none.
    Returns: None.
    Fails:   never.
    Feeds:   agent/server main."""
    global _enabled
    _enabled = True


def enabled():
    """Purpose: whether this process holds its requests' processes.
    Inputs:  none.
    Returns: bool.
    Fails:   never.
    Feeds:   run_op, read_in_dc."""
    return _enabled


def _spawn(container):
    """Purpose: one held process in the DC.
    Inputs:  container — the DC's container.
    Returns: subprocess.Popen.
    Fails:   OSError when docker is not there.
    Feeds:   _take."""
    return subprocess.Popen(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                             "/fabric/directory_op.py", "--serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)


def _take(container, deadline):
    """Purpose: a free held process, one made if fewer than MAX_HELD are running, or wait for one.
    Inputs:  container — str; deadline — time.monotonic() to give up at.
    Returns: subprocess.Popen.
    Fails:   subprocess.TimeoutExpired past the deadline; OSError from _spawn.
    Feeds:   send."""
    with _lock:
        while True:
            free = _idle.setdefault(container, [])
            while free:
                proc = free.pop()
                if proc.poll() is None:
                    return proc
                _count[container] -= 1          # it died while idle: the DC restarted
            if _count.get(container, 0) < MAX_HELD:
                _count[container] = _count.get(container, 0) + 1
                try:
                    return _spawn(container)
                except OSError:
                    _count[container] -= 1
                    raise
            left = deadline - time.monotonic()
            if left <= 0:
                raise subprocess.TimeoutExpired("held directory process", 0)
            _lock.wait(left)


def _give(container, proc, keep):
    """Purpose: a process handed back, or ended for good when its answer went wrong.
    Inputs:  container — str; proc — subprocess.Popen; keep — bool.
    Returns: None.
    Fails:   never.
    Feeds:   send."""
    with _lock:
        if keep:
            _idle.setdefault(container, []).append(proc)
        else:
            _count[container] -= 1
        _lock.notify()
    if not keep:
        proc.kill()
        proc.wait()


def _read_line(proc, deadline):
    """Purpose: the process's next line, by a deadline.
    Inputs:  proc — subprocess.Popen; deadline — time.monotonic().
    Returns: bytes; empty when it ended first.
    Fails:   subprocess.TimeoutExpired past the deadline.
    Feeds:   send."""
    fd, buf = proc.stdout.fileno(), b""
    while not buf.endswith(b"\n"):
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            raise subprocess.TimeoutExpired("held directory process", 0)
        chunk = os.read(fd, 65536)
        if not chunk:
            return b""
        buf += chunk
    return buf


def send(container, request, timeout=60):
    """Purpose: one operation through a held process. One whose files changed (an update copied new ones) answers
             {"restart": true} without doing anything, and is replaced and asked again.
    Inputs:  container — the DC's container; request — directory_op's request; timeout — seconds.
    Returns: the answer's dict ({"result"} or {"error", "kind"}).
    Fails:   ValueError for no answer (the process ended, the DC stopped); subprocess.TimeoutExpired; OSError.
    Feeds:   run_op."""
    deadline = time.monotonic() + timeout
    line = (json.dumps(request) + "\n").encode()
    for _ in range(3):
        proc = _take(container, deadline)
        keep = False
        try:
            try:
                proc.stdin.write(line)
                proc.stdin.flush()
            except OSError:         # it ended before it read anything: nothing was done, so a new one may be asked
                continue
            raw = _read_line(proc, deadline)
            if not raw:
                raise ValueError("the held process ended without an answer")
            answer = json.loads(raw)
            if answer.get("restart"):
                continue
            keep = True
            return answer
        finally:
            _give(container, proc, keep)
    raise ValueError("no held process would answer")


def ask_tool(container, tool, request):
    """Purpose: one read of a DC tool (grants_tool, gpo_tool) through a held process, for run-through callers.
    Inputs:  container — the DC's container; tool — its name; request — its request.
    Returns: the tool's answer ({"result"} or {"error"}).
    Fails:   ValidationError when the DC does not answer; subprocess.TimeoutExpired after 60 s.
    Feeds:   grant_request, gpo_request."""
    try:
        return send(container, {"tool": tool, "request": request})
    except (ValueError, OSError) as e:
        raise ValidationError("the domain controller is not running") from e


def forget(container=None):
    """Purpose: end the held processes (tests; a process that must not outlive its caller).
    Inputs:  container — one container, or None for all.
    Returns: None.
    Fails:   never.
    Feeds:   tests."""
    with _lock:
        for name in ([container] if container else list(_idle)):
            for proc in _idle.pop(name, []):
                proc.kill()
                proc.wait()
            _count[name] = 0
