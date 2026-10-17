"""A zone installed under a running BIND that is about to restart (fabriclib/dns/freeze_and_install, 2.3.1.23):
`rndc freeze` answers before BIND has written the zone's journal into its file, and that write used to land after the
new file and put the old zone back (the sandbox's changed-setting record, not served). rndc stood in for, BIND's late
write simulated by a thread. Part of the `zone` suite. No Docker, no BIND.
    python3 tests/dns/freeze_and_install_test.py"""
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.dns import freeze_and_install as module  # noqa: E402
from fabriclib.dns.freeze_and_install import freeze_and_install  # noqa: E402

PASS = FAIL = 0
OLD = "@ IN SOA ns hostmaster ( 100 ; Serial\n 1 1 1 1 1 )\nold A 10.77.0.1\n"
NEW = "@ IN SOA ns hostmaster ( 200 ; Serial\n 1 1 1 1 1 )\nrerun-test A 10.77.0.99\n"


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


class R:
    def __init__(self, rc):
        self.returncode, self.stdout, self.stderr = rc, "", ""


def bind(delay, rc=0, writes=True):
    """rndc as BIND answers a freeze: at once, its write of the old zone (journal synced) `delay` seconds later."""
    calls = []

    def fake(args, timeout=15):
        calls.append(" ".join(args))
        if writes and args[0] == "freeze" and rc == 0:
            dst = os.path.join(FOLDER, f"db.{args[-1]}")

            def late():
                time.sleep(delay)
                tmp = dst + ".tmp"
                with open(tmp, "w") as f:
                    f.write(OLD + "dhcp-name A 10.77.0.201\n")
                os.replace(tmp, dst)             # BIND writes a temporary file, then renames it
            threading.Thread(target=late).start()
        return R(rc)
    module.rndc = fake
    return calls


def setup(journal=True):
    for name in os.listdir(FOLDER):
        os.remove(os.path.join(FOLDER, name))
    with open(os.path.join(FOLDER, "db.lan.test"), "w") as f:
        f.write(OLD)
    if journal:                                       # changes since the file was written: BIND will write them
        jnl = os.path.join(FOLDER, "db.lan.test.jnl")
        open(jnl, "w").close()
        os.utime(os.path.join(FOLDER, "db.lan.test"), (time.time() - 60, time.time() - 60))
    src = os.path.join(RENDER, "db.lan.test")
    with open(src, "w") as f:
        f.write(NEW)
    return src, os.path.join(FOLDER, "db.lan.test")


with tempfile.TemporaryDirectory() as FOLDER, tempfile.TemporaryDirectory() as RENDER:
    ids = (os.getuid(), os.getgid())

    src, dst = setup()
    calls = bind(0.3)
    seen = freeze_and_install("lan.test", src, dst, *ids)
    time.sleep(0.5)                                   # anything still to land has landed
    check("BIND's late write (0.3 s after the freeze answered) is waited for; the new zone stays in place",
          seen and open(dst).read() == NEW and calls == ["freeze lan.test"], (seen, open(dst).read(), calls))
    check("the journal written against the old file is gone", not os.path.exists(dst + ".jnl"))

    src, dst = setup(journal=False)
    calls = bind(0.1, writes=False)
    t = time.monotonic()
    seen = freeze_and_install("lan.test", src, dst, *ids)
    check("no journal: nothing for BIND to write, no wait, installed", seen and time.monotonic() - t < 0.5
          and open(dst).read() == NEW, (seen, time.monotonic() - t))

    src, dst = setup(journal=False)
    open(dst + ".jnl", "w").close()
    os.utime(dst + ".jnl", (time.time() - 60, time.time() - 60))       # older than the file: already written
    calls = bind(0.1, writes=False)
    t = time.monotonic()
    seen = freeze_and_install("lan.test", src, dst, *ids)
    check("a journal older than the file (BIND wrote it already): no wait, installed",
          seen and time.monotonic() - t < 0.5 and open(dst).read() == NEW, (seen, time.monotonic() - t))

    src, dst = setup()
    calls = bind(0.1, rc=1)
    t = time.monotonic()
    seen = freeze_and_install("lan.test", src, dst, *ids)
    check("a static zone (freeze refused): installed at once", seen and time.monotonic() - t < 0.5
          and open(dst).read() == NEW, (seen, time.monotonic() - t))

    src, dst = setup()
    calls = bind(0, writes=False)                     # a journal, but BIND had nothing left to write
    t = time.monotonic()
    seen = freeze_and_install("lan.test", src, dst, *ids, wait=0.4)
    check("no write within the wait: installed after it, said so", not seen and 0.35 < time.monotonic() - t < 1.5
          and open(dst).read() == NEW, (seen, time.monotonic() - t))

print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
