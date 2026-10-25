"""unit_running (decision 2.1.2.26): whether fabric-setup.service runs, from `systemctl is-active` (stubbed).
    python3 tests/setup/detach/unit_running_test.py"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
from fabriclib.setup.detach.unit_running import unit_running  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


calls = []


def says(text, code=0):
    def run(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(stdout=text + "\n", returncode=code)
    return run


check("active: running", unit_running(says("active")))
check("…asked of fabric-setup.service", calls[-1] == ["systemctl", "is-active", "fabric-setup.service"], calls)
check("activating and deactivating: running (its process may still write its log)",
      unit_running(says("activating", 3)) and unit_running(says("deactivating", 3)))
check("negative: inactive (a finished unit is unloaded by --collect): not running",
      not unit_running(says("inactive", 3)))
check("negative: failed: not running", not unit_running(says("failed", 3)))


def missing(cmd, **kw):
    raise FileNotFoundError("systemctl")


check("negative: no systemctl: not running", not unit_running(missing))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
