"""can_detach (decision 2.1.2.26): setup's work runs as a unit only on a host booted with systemd, with systemd-run.
    python3 tests/setup/detach/can_detach_test.py"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
from fabriclib.setup.detach.can_detach import can_detach  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


with tempfile.TemporaryDirectory() as d:
    check("booted with systemd and systemd-run on PATH: yes (as far as this machine has systemd-run)",
          can_detach(d) == (shutil.which("systemd-run") is not None))
    check("negative: not booted with systemd (no /run/systemd/system): no",
          not can_detach(os.path.join(d, "missing")))
    saved = os.environ.get("PATH", "")
    os.environ["PATH"] = d                     # an empty folder: no systemd-run
    try:
        check("negative: no systemd-run: no", not can_detach(d))
    finally:
        os.environ["PATH"] = saved

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
