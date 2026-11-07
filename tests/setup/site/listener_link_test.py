#!/usr/bin/env python3
"""What root does with a listener that misbehaves (manual 1.3.6.3): it runs as nobody, so what it says is not trusted to be
well formed, and it must not be able to stop setup. A real socket pair, and a real process for the stop.
    python3 tests/setup/site/listener_link_test.py"""
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import check, finish  # noqa: E402

from fabriclib.setup.site import listener_link as ll  # noqa: E402


def pump_with(*lines):
    """What the reading thread does with these lines: (messages it passed on, whether ready was said, whether it ended)."""
    ours, theirs = socket.socketpair()
    link = ll.ListenerLink("/nowhere", None)
    ready, got = threading.Event(), []
    thread = threading.Thread(target=link._pump, args=(ours, ready, got.append), daemon=True)
    thread.start()
    for line in lines:
        theirs.sendall(line)
    thread.join(3)
    ended = not thread.is_alive()
    theirs.close()
    ours.close()
    return got, ready.is_set(), ended


got, ready, ended = pump_with(b'{"t": "ready"}\n', b'{"t": "code", "code": "x"}\n')
check("well-formed messages reach setup; ready is kept for the start", ready and got == [{"t": "code", "code": "x"}], got)
got, _, ended = pump_with(b'[1, 2]\n', b'{"t": "code"}\n')
check("a line that is no message ends the link, and nothing after it is taken", ended and got == [], got)
got, _, ended = pump_with(b'{not json\n', b'{"t": "code"}\n')
check("a line that is no JSON ends the link, without an exception", ended and got == [], got)
sender = threading.Thread(target=lambda: pump_with(b"x" * (ll.MAX_LINE + 10)), daemon=True)
sender.start()
sender.join(10)
check("an endless line ends the link: root's memory does not grow with it", not sender.is_alive())

ours, theirs = socket.socketpair()
saved, ll.SEND_SECONDS = ll.SEND_SECONDS, 1
link = ll.ListenerLink("/nowhere", None)
link.link = ours
ours.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, ll.struct.pack("ll", 1, 0))
began = time.monotonic()
for _ in range(3):
    link.send({"t": "log", "text": "x" * 1_000_000})
check("a listener that stops reading: sending gives up, and setup goes on", time.monotonic() - began < 15, time.monotonic() - began)
ll.SEND_SECONDS = saved
ours.close()
theirs.close()

# a process that ends when its link does, read from a thread as setup's is
ours, theirs = socket.socketpair()
process = subprocess.Popen([sys.executable, "-c", "import socket,sys\ns = socket.socket(fileno=int(sys.argv[1]))\nwhile s.recv(99): pass\n",
                            str(theirs.fileno())], pass_fds=[theirs.fileno()], stderr=subprocess.DEVNULL)
process.errors_file = open(os.devnull, "rb")
theirs.close()
link = ll.ListenerLink("/nowhere", None)
link.process, link.link = process, ours
threading.Thread(target=link._pump, args=(ours, threading.Event(), lambda m: None), daemon=True).start()
time.sleep(0.2)
began = time.monotonic()
link.stop()
took = time.monotonic() - began
check("a stop ends the listener at once, though the reading thread holds the link", took < 2 and process.returncode == 0, (took, process.returncode))

sys.exit(finish("listener_link_test"))
