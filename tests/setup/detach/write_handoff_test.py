"""write_handoff (manual 1.3.2.3.4): the secrets typed in setup's questions go to the unit in a new 0600 file,
never through a planted file or symlink.
    python3 tests/setup/detach/write_handoff_test.py"""
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
import yaml  # noqa: E402

from fabriclib.setup.detach.write_handoff import write_handoff  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


with tempfile.TemporaryDirectory() as d:
    where = os.path.join(d, "run-fabric")
    path = write_handoff("r1", {"admin_password": "Good-Pass-1234"}, where)
    check("the hand-off file is <dir>/setup-<run>.handoff, 0600, in a folder made 0700",
          path == os.path.join(where, "setup-r1.handoff") and stat.S_IMODE(os.stat(path).st_mode) == 0o600
          and stat.S_IMODE(os.stat(where).st_mode) == 0o700, (path, oct(os.stat(path).st_mode)))
    check("…holding the secrets", yaml.safe_load(open(path)) == {"admin_password": "Good-Pass-1234"})
    try:
        write_handoff("r1", {"admin_password": "other"}, where)
        check("negative: an existing file is refused, never overwritten", False)
    except FileExistsError:
        check("negative: an existing file is refused, never overwritten",
              yaml.safe_load(open(path)) == {"admin_password": "Good-Pass-1234"})
    target = os.path.join(d, "elsewhere")
    open(target, "w").write("untouched\n")
    os.symlink(target, os.path.join(where, "setup-r2.handoff"))
    try:
        write_handoff("r2", {"admin_password": "x"}, where)
        check("negative: a planted symlink is refused, its target untouched", False)
    except OSError:
        check("negative: a planted symlink is refused, its target untouched", open(target).read() == "untouched\n")
    for bad in ("../r3", "", ".hidden"):
        try:
            write_handoff(bad, {"a": "b"}, where)
            check(f"negative: run id {bad!r} is refused", False)
        except ValueError:
            check(f"negative: run id {bad!r} is refused", True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
