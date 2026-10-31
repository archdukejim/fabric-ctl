"""follow_run (decision 2.1.2.26, manual 1.3.2.3.2): the console prints the run's log as it grows until the unit
ends, then exits with the run's result; Ctrl-C detaches, saying the work goes on. The unit and the clock are stubbed:
each pause appends the next piece of the log.
    python3 tests/setup/detach/follow_run_test.py"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
from fabriclib.setup.detach.follow_run import follow_run  # noqa: E402
from fabriclib.setup.detach.write_run import write_run  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


class Unit:
    """A run that writes pieces of its log, one per pause, then ends with the record's state."""
    def __init__(self, d, pieces, state, result=0, interrupt_after=None):
        self.d, self.pieces, self.state, self.result = d, list(pieces), state, result
        self.interrupt_after, self.pauses = interrupt_after, 0
        self.log = os.path.join(d, "setup-run.log")
        open(self.log, "wb").close()

    def running(self):
        return bool(self.pieces)

    def sleep(self, _):
        self.pauses += 1
        if self.interrupt_after is not None and self.pauses > self.interrupt_after:
            raise KeyboardInterrupt
        with open(self.log, "ab") as f:
            f.write(self.pieces.pop(0))
        if not self.pieces:
            write_run(self.d, {"id": "r1", "state": self.state, "result": self.result})


def follow(unit):
    out = io.StringIO()
    err = io.StringIO()
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err              # info() and err() print to these
    try:
        code = follow_run(unit.d, running=unit.running, out=out, sleep=unit.sleep, interval=0)
    finally:
        sys.stdout, sys.stderr = saved
    return code, out.getvalue(), err.getvalue()


with tempfile.TemporaryDirectory() as d:
    write_run(d, {"id": "r1", "state": "running"})
    snow = "✓".encode()
    pieces = [b"\n[preflight] check\n", b"  " + snow[:2], snow[2:] + b" ok\n", b"\nfabric is ready (3s)\n"]
    code, out, _ = follow(Unit(d, pieces, "done"))
    check("the whole log is shown as it grows, and a finished run exits 0",
          code == 0 and out == "\n[preflight] check\n  ✓ ok\n\nfabric is ready (3s)\n", (code, out))
    check("…a character split between two reads is shown whole", "✓ ok" in out, out)

with tempfile.TemporaryDirectory() as d:
    write_run(d, {"id": "r1", "state": "running"})
    code, out, _ = follow(Unit(d, [b"[certs] issue\n", b"  x the CA did not answer\n"], "failed", 1))
    check("negative: a run a step stopped exits 1, its message shown", code == 1 and "did not answer" in out, (code, out))

with tempfile.TemporaryDirectory() as d:
    write_run(d, {"id": "r1", "state": "running"})
    code, out, _ = follow(Unit(d, [b"[start] x\n"], "failed", 130))
    check("negative: a step interrupted in the unit exits 130", code == 130, code)

with tempfile.TemporaryDirectory() as d:
    write_run(d, {"id": "r1", "state": "running"})
    unit = Unit(d, [b"[certs] issue\n"], "running")
    code, out, err = follow(unit)
    check("negative: the unit ended without recording an end (killed): exit 1, saying setup resumes when run again",
          code == 1 and "ended before setup finished" in err and "resumes" in err, (code, err))

with tempfile.TemporaryDirectory() as d:
    write_run(d, {"id": "r1", "state": "running"})
    unit = Unit(d, [b"[certs] issue\n", b"more\n", b"end\n"], "done", interrupt_after=1)
    code, out, _ = follow(unit)
    check("Ctrl-C detaches: exit 130, saying the work goes on and how to follow it again, the unit untouched",
          code == 130 and "does not stop it" in out and "sudo fabricctl setup" in out and unit.pieces, (code, out))

with tempfile.TemporaryDirectory() as d:
    out = io.StringIO()
    saved = sys.stderr
    sys.stderr = out
    try:
        code = follow_run(d, running=lambda: False, out=io.StringIO(), sleep=lambda s: None, interval=0)
    finally:
        sys.stderr = saved
    check("negative: no log and no unit: exit 1, naming journalctl", code == 1 and "journalctl" in out.getvalue(),
          (code, out.getvalue()))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
