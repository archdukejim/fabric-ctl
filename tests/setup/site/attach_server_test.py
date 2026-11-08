#!/usr/bin/env python3
"""The running setup's attach socket (manual 1.3.6.7, decision 2.1.8.60): root's only, one way, a stuck terminal
dropped. Real Unix sockets; the peer that is not root is a real process under another uid (as root only).
    python3 tests/setup/site/attach_server_test.py"""
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import check, finish  # noqa: E402

from fabriclib.setup.site.attach_server import AttachServer  # noqa: E402


def read_some(sock, want, seconds=5):
    got, deadline = b"", time.time() + seconds
    sock.settimeout(0.5)
    while want not in got and time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        got += chunk
    return got.decode()


base = tempfile.mkdtemp(prefix="fabric-attach-")
path = os.path.join(base, "run", "site-attach.sock")
os.makedirs(os.path.dirname(path))
stale = socket.socket(socket.AF_UNIX)
stale.bind(path)                           # what a killed setup left
stale.close()
server = AttachServer(lambda: "GREETING code X\n", path).open()
check("a socket a killed setup left is replaced", os.path.exists(path) and stat.S_ISSOCK(os.lstat(path).st_mode))
check("the socket is root's only: 0600", stat.S_IMODE(os.stat(path).st_mode) == 0o600)

a = socket.socket(socket.AF_UNIX)
a.connect(path)
check("an attach gets the greeting first", "GREETING code X" in read_some(a, b"GREETING"))
b = socket.socket(socket.AF_UNIX)
b.connect(path)
read_some(b, b"GREETING")
server.say("a line setup printed\n")
check("what setup prints reaches every attached terminal", "a line setup printed" in read_some(a, b"printed") and "a line setup printed" in read_some(b, b"printed"))
a.sendall(b"stop\nanything\n")
server.say("still going\n")
check("what a terminal sends is never read as a command: setup goes on", "still going" in read_some(a, b"going"))

stuck = socket.socket(socket.AF_UNIX)
stuck.connect(path)
time.sleep(0.3)
began = time.time()
for _ in range(8):
    server.say("x" * 500_000)
took = time.time() - began
check("a terminal that stops reading is dropped, and setup goes on", took < 20 and len(server.viewers) < 3, (took, len(server.viewers)))

if os.geteuid() == 0:
    os.chmod(path, 0o666)                  # only so the other uid reaches the peer check at all
    os.chmod(os.path.dirname(path), 0o755)
    os.chmod(base, 0o755)
    probe = ("import socket,sys\ns = socket.socket(socket.AF_UNIX)\ns.connect(sys.argv[1])\ns.settimeout(3)\n"
             "print(repr(s.recv(999)))\n")
    out = subprocess.run([sys.executable, "-c", probe, path], user=65534, capture_output=True, text=True, timeout=10)
    check("a peer that is not root is closed unanswered", out.stdout.strip() == "b''", (out.stdout, out.stderr[-200:]))
else:
    print("  skip: the peer check needs root (a process under another uid)")

open_path = os.path.join(base, "not-a-socket")
open(open_path, "w").close()
try:
    AttachServer(lambda: "", open_path).open()
    check("a file that is no socket at the path is never removed", False)
except OSError:
    check("a file that is no socket at the path is never removed: refused", os.path.isfile(open_path))

late = socket.socket(socket.AF_UNIX)        # the terminals above stopped reading too, and were dropped with it
late.connect(path)
read_some(late, b"GREETING")
server.close("bye\n")
check("close tells each terminal, ends it, and removes the socket", "bye" in read_some(late, b"bye") and not os.path.exists(path))
check("a second close does nothing", server.close() is None)

sys.exit(finish("attach_server_test"))
