"""read_run (manual 1.3.2.3.3): the last run's record, None when there is none or it is damaged.
    python3 tests/setup/detach/read_run_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
from fabriclib.setup.detach.read_run import read_run  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "setup-run.yaml")
    check("negative: no record: None", read_run(d) is None)
    open(path, "w").write("id: r1\nstate: failed\ndone: [preflight]\n")
    got = read_run(d)
    check("a record is read", got == {"id": "r1", "state": "failed", "done": ["preflight"]}, got)
    for text, why in (("id: [unclosed\n", "does not parse"), ("- a list\n", "is not a mapping"),
                      ("state: failed\n", "has no id"), ("", "is empty")):
        open(path, "w").write(text)
        check(f"negative: a record that {why} reads as none (setup starts over: its steps are idempotent)",
              read_run(d) is None)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
