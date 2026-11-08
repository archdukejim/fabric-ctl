#!/usr/bin/env python3
"""`sudo fabricctl setup` while a site runs (manual 4.3.6.5, decision 2.1.8.60): it attaches, follows, and Ctrl-C only
detaches; a socket it cannot reach is refused, saying why. Real Unix sockets and a real SIGINT.
    python3 tests/setup/site/attach_site_test.py"""
import io
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import check, finish  # noqa: E402

from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.site.attach_server import AttachServer  # noqa: E402
from fabriclib.setup.site.attach_site import attach_site  # noqa: E402

RECORD = {"port": 8443, "pid": 4242}
base = tempfile.mkdtemp(prefix="fabric-attach-")
path = os.path.join(base, "site-attach.sock")

try:
    attach_site(RECORD, path, io.StringIO())
    check("no socket", False)
except SetupError as e:
    check("no socket to reach: refused, naming the running site, nothing changed", "process 4242" in str(e) and "TCP 8443" in str(e) and "Nothing was changed" in str(e), e)

server = AttachServer(lambda: "  One-time code:  ABCD-EFGH\n", path).open()
out = io.StringIO()
threading.Timer(0.5, lambda: server.say("caf\u00e9 line\n")).start()
threading.Timer(1.0, lambda: server.close()).start()
result = attach_site(RECORD, path, out)
check("attached: the code, then what setup prints, a character split across reads kept whole",
      result == 0 and "ABCD-EFGH" in out.getvalue() and "caf\u00e9 line" in out.getvalue(), out.getvalue())
check("the site's end ends the attach, saying so", "has stopped" in out.getvalue())

server = AttachServer(lambda: "hello\n", path).open()
out = io.StringIO()
threading.Timer(0.5, os.kill, (os.getpid(), signal.SIGINT)).start()
result = attach_site(RECORD, path, out)
time.sleep(0.2)
check("Ctrl-C only detaches: setup's socket is still there", result == 0 and "Detached" in out.getvalue() and os.path.exists(path), out.getvalue())
server.say("after the detach\n")
check("and setup goes on, with no terminal left", server.viewers == [] and server.sock is not None)
server.close()

if os.geteuid() == 0:
    server = AttachServer(lambda: "", path).open()
    os.chmod(base, 0o755)
    probe = ("import sys\nsys.path.insert(0, sys.argv[2])\nfrom fabriclib.setup.site.attach_site import attach_site\n"
             "from fabriclib.setup.errors import SetupError\ntry:\n    attach_site({'port': 1, 'pid': 1}, sys.argv[1])\n"
             "except SetupError as e:\n    print(e)\n")
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src")
    done = subprocess.run([sys.executable, "-c", probe, path, os.path.abspath(src)], user=65534, capture_output=True,
                          text=True, timeout=10)
    check("a user who is not root: refused, told to use sudo", "only root can attach" in done.stdout, (done.stdout, done.stderr[-300:]))
    server.close()
else:
    print("  skip: the refusal of another user needs root")

sys.exit(finish("attach_site_test"))
