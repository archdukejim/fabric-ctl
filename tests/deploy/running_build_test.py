"""What the apply records of the build its services run (decision 2.1.1.83): a change of build is seen, and a record that
cannot be written says so without failing an apply whose work is done (2.3.1.53).
    python3 tests/deploy/running_build_test.py"""
import contextlib
import io
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.deploy.running_build as rb  # noqa: E402

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:300]}"))


def recording(folder):
    said = io.StringIO()
    with contextlib.redirect_stdout(said):
        kept = rb.record_build(folder)
    return kept, said.getvalue()


rb.version_info = lambda: {"version": "1.2.3", "build": "abc"}
with tempfile.TemporaryDirectory() as d:
    check("no build recorded yet: counted as changed", rb.build_changed(d) is True)
    kept, said = recording(d)
    check("recorded, saying nothing, and no longer changed", kept is True and not said and rb.build_changed(d) is False, said)
    rb.version_info = lambda: {"version": "1.2.4", "build": "abc"}
    check("a new build is seen", rb.build_changed(d) is True)
    missing = os.path.join(d, "not-here")
    kept, said = recording(missing)
    check("negative: the folder missing: no exception, not recorded, and it says what the next apply will do",
          kept is False and "could not record this build" in said and "next apply" in said and not os.path.exists(missing), said)
    # a path that cannot be a folder fails for root too, as a read-only or full disk would
    afile = os.path.join(d, "a-file")
    with open(afile, "w") as f:
        f.write("x")
    os.chmod(afile, stat.S_IRUSR)
    kept, said = recording(afile)
    check("negative: not writable there: no exception, not recorded, says so", kept is False and "could not record" in said, said)
    check("...and an unwritten record still counts as changed, so the services are not left on old code",
          rb.build_changed(missing) is True)
print("all passed" if not FAILED else f"FAILED ({FAILED})")
sys.exit(1 if FAILED else 0)
